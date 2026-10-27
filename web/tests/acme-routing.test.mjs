import test from "node:test";
import assert from "node:assert/strict";
import { build } from "vite";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { execFileSync, spawn } from "node:child_process";
import http from "node:http";
import net from "node:net";
import { once } from "node:events";

const listen = async (server) => {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return server.address().port;
};
const freePort = async () => {
  const server = net.createServer();
  const port = await listen(server);
  await new Promise((resolve) => server.close(resolve));
  return port;
};

// Run with NGINX_TEST_BIN=/path/to/nginx node --test tests/acme-routing.test.mjs.
test(
  "HTTP-01 bypasses redirects, regex locations and basic auth in real Nginx",
  {
    skip: !process.env.NGINX_TEST_BIN,
    timeout: 30000,
  },
  async (t) => {
    const dir = await mkdtemp(path.join(tmpdir(), "nginx-master-routing-"));
    t.after(() => rm(dir, { recursive: true, force: true }));
    const outfile = path.join(dir, "config.mjs");
    const entry = path.join(dir, "entry.ts");
    await writeFile(
      entry,
      `export { makeNginxServerConfig } from ${JSON.stringify(
        path.resolve("src/common/makeNginxConfig.ts")
      )}; export { newServerConfig, newLocationConfig } from ${JSON.stringify(
        path.resolve("src/common/newConfig.ts")
      )};`
    );
    await build({
      configFile: false,
      logLevel: "silent",
      build: {
        lib: { entry, formats: ["es"], fileName: () => "config.mjs" },
        outDir: dir,
        emptyOutDir: false,
        minify: false,
      },
    });
    const { makeNginxServerConfig, newServerConfig, newLocationConfig } =
      await import(pathToFileURL(outfile));
    const backend = http.createServer((req, res) => {
      if (
        req.url === "/.well-known/acme-challenge/active-token" &&
        req.headers.host === "example.com"
      ) {
        res.end("challenge-response");
      } else {
        res.writeHead(404);
        res.end("unknown token");
      }
    });
    const backendPort = await listen(backend);
    t.after(() => new Promise((resolve) => backend.close(resolve)));
    const httpPort = await freePort();
    const httpsPort = await freePort();
    execFileSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        path.join(dir, "cert.key"),
        "-out",
        path.join(dir, "cert.pem"),
        "-days",
        "1",
        "-subj",
        "/CN=example.com",
      ],
      { stdio: "ignore" }
    );
    const template = await readFile("../srv/nginx.conf", "utf8");
    const maps = template.slice(
      template.indexOf("    map $uri"),
      template.indexOf("    include             @NginxConfigDir@")
    );
    const config = newServerConfig();
    Object.assign(config, {
      domains: ["example.com"],
      httpPorts: [httpPort],
      sslEn: true,
      sslPorts: [httpsPort],
      sslCertPem: path.join(dir, "cert.pem"),
      sslCertKey: path.join(dir, "cert.key"),
      sslHttp2En: false,
      sslForceEn: true,
      staticCacheEn: false,
      nginxRaw: `auth_basic "Restricted";\nauth_basic_user_file ${dir}/missing-password-file;`,
      locations: [
        {
          ...newLocationConfig(),
          mode: "redirect",
          redirect_target: "https://destination.example",
          redirect_takeUri: true,
        },
        {
          ...newLocationConfig(),
          path: "~ /\\.",
          mode: "custom",
          nginxRaw: "return 403;",
        },
      ],
    });
    const configPath = path.join(dir, "nginx.conf");
    const writeConfig = async () => {
      const server = makeNginxServerConfig(config).replaceAll(
        "127.0.0.1:9999",
        `127.0.0.1:${backendPort}`
      );
      await writeFile(
        configPath,
        `daemon off;\nmaster_process off;\npid ${dir}/nginx.pid;\nerror_log ${dir}/error.log;\nevents {}\nhttp {\naccess_log off;\nclient_body_temp_path ${dir}/body;\nproxy_temp_path ${dir}/proxy;\n${maps}\n${server}\n}`
      );
      execFileSync(
        process.env.NGINX_TEST_BIN,
        ["-t", "-p", dir, "-c", configPath],
        { stdio: "pipe" }
      );
    };
    const request = (uri) =>
      new Promise((resolve, reject) => {
        http
          .get(
            {
              host: "127.0.0.1",
              port: httpPort,
              path: uri,
              headers: { Host: "example.com" },
            },
            (res) => {
              let body = "";
              res.on("data", (part) => (body += part));
              res.on("end", () =>
                resolve({
                  status: res.statusCode,
                  body,
                  location: res.headers.location,
                })
              );
            }
          )
          .on("error", reject);
      });
    const start = async () => {
      const child = spawn(
        process.env.NGINX_TEST_BIN,
        ["-p", dir, "-c", configPath],
        { stdio: "ignore" }
      );
      let stopped = false;
      const stop = async () => {
        if (stopped || child.exitCode !== null) return;
        stopped = true;
        child.kill("SIGTERM");
        await once(child, "exit");
      };
      t.after(stop);
      for (let attempt = 0; attempt < 100; attempt++) {
        try {
          await request("/ready");
          return stop;
        } catch {}
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
      throw new Error(await readFile(path.join(dir, "error.log"), "utf8"));
    };
    await writeConfig();
    let stop = await start();
    const challenge = await request("/.well-known/acme-challenge/active-token");
    assert.equal(challenge.status, 200);
    assert.equal(challenge.body, "challenge-response");
    assert.equal(
      (await request("/.well-known/acme-challenge/unknown")).status,
      404
    );
    const redirect = await request("/normal-page");
    assert.equal(redirect.status, 301);
    assert.equal(
      redirect.location,
      `https://example.com:${httpsPort}/normal-page`
    );
    await stop();
    config.sslForceEn = false;
    config.sslEn = false;
    await writeConfig();
    stop = await start();
    assert.equal(
      (await request("/.well-known/acme-challenge/active-token")).status,
      200
    );
    assert.equal(
      (await request("/normal-page")).location,
      "https://destination.example/normal-page"
    );
    await stop();
  }
);
