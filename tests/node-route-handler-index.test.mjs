import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";

test("repository index records only simple named Node route handlers", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-node-routes-"));
  try {
    const source = [
      "function listUsers(req, res) { res.json([]); }",
      "router.get('/users', requireAuth, listUsers);",
      "router.post('/users', (req, res) => res.sendStatus(204));",
      "router.use('/admin', adminRouter);",
      "router.patch('/users/:id', requireAuth(), updateUser);",
    ].join("\n");
    await writeFile(join(root, "server.ts"), source, "utf8");
    const index = await buildRepositoryIndex(root, [{ path: "server.ts", size: Buffer.byteLength(source) }]);

    assert.equal(index.routes.length, 4);
    const getUsers = index.routes.find((route) => route.method === "GET" && route.route === "/users");
    const postUsers = index.routes.find((route) => route.method === "POST" && route.route === "/users");
    const admin = index.routes.find((route) => route.method === "USE" && route.route === "/admin");
    const patchUser = index.routes.find((route) => route.method === "PATCH" && route.route === "/users/:id");

    assert.equal(getUsers?.handler, "listUsers");
    assert.equal(postUsers?.handler, undefined);
    assert.equal(admin?.handler, undefined);
    assert.equal(patchUser?.handler, undefined);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
