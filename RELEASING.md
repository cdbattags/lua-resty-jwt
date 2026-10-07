# Releasing

Publishing a (non-pre-release) GitHub release for tag `vX.Y.Z` runs
[`publish.yml`](.github/workflows/publish.yml). The workflow checks that the
tag matches `_VERSION`, runs `./ci`, and then uploads `X.Y.Z-1` to LuaRocks
and `X.Y.Z` to OPM. Neither upload can be overwritten, so do every step
below in order.

## 1. Prepare (on the release branch, before merging to master)

1. **Bump `_VERSION`** in `lib/resty/jwt.lua`. It is the only place a version
   lives: OPM reads it, the tag must match it, and `t/version.t` fails if the
   rockspec or `dist.ini` hard-codes one.
2. **Write the release notes** in [`CHANGELOG.md`](CHANGELOG.md): replace
   `UNRELEASED` with the release date and every `GHSA-TBD` with the advisory
   IDs, and use the version's section as the GitHub release body. Cover:
   - breaking changes
   - dependency floor changes (currently `lua-resty-openssl >= 1.1.0` on
     LuaRocks and `>= 1.2.0` on OPM)
   - deprecations: the vendored `resty.hmac` is still shipped in the rock but
     is removed in 1.0 (OPM no longer pulls it in), and
     `set_legacy_ecdh_kw_kdf` is removed in 1.0
   - the GHSA IDs being fixed
3. **Run the suite**: `./ci`
4. **Dry-run both packages**: `./ci-release-dry-run X.Y.Z`. Nothing is
   uploaded. The script works on a copy of the checkout in a throwaway
   `cdbattags/openresty-testsuite` container and runs:

   ```sh
   # OPM, with a dummy ~/.opmrc whose upload_server is http://127.0.0.1:9
   opm build                  # must report "extracted verson number X.Y.Z"
   # loads every module from the tarball with only the OPM dependencies

   # LuaRocks
   luarocks new_version lua-resty-jwt-dev-0.rockspec X.Y.Z-1 \
     git+https://github.com/cdbattags/lua-resty-jwt.git --tag=vX.Y.Z
   luarocks lint lua-resty-jwt-X.Y.Z-1.rockspec
   luarocks make lua-resty-jwt-X.Y.Z-1.rockspec   # builds from the checkout
   prove -j4 -r t

   # every rockspec module is in both packages, then publish.yml's guard
   RELEASE_TAG=vX.Y.Z prove t/version.t
   ```

   It must end with `==> dry run OK for X.Y.Z`. During `new_version`,
   LuaRocks prints a harmless `Warning: invalid URL ... git+https`, because
   it can't fetch a git URL to checksum it.
5. **Check the publish credentials** (nothing is uploaded). Once
   `check-credentials.yml` is on `master`, run it from the Actions tab
   (*Check publish credentials* → *Run workflow*), or run it locally without
   leaving the values in your shell history:

   ```sh
   read -rs LUAROCKS_API_KEY; read -rs OPM_GITHUB_TOKEN
   export LUAROCKS_API_KEY OPM_GITHUB_TOKEN OPM_GITHUB_ACCOUNT=cdbattags
   ./ci-check-credentials
   ```

   It calls LuaRocks' `/api/1/<key>/status` (the first call `luarocks upload`
   makes) and GitHub's `/user` with the OPM token. It checks that the token
   belongs to `OPM_GITHUB_ACCOUNT` (or an org it's a member of), that it has
   opm's required `user:email` and `read:org` scopes, and that it doesn't
   expire within 7 days. It never prints a credential. `publish.yml` runs the
   same check before either upload.

   To rotate a credential, update the repository secret (the value is read
   from stdin, so it isn't echoed or stored in history):

   ```sh
   gh secret set LUAROCKS_API_KEY --repo cdbattags/lua-resty-jwt   # new key from https://luarocks.org/settings/api-keys
   gh secret set OPM_GITHUB_TOKEN --repo cdbattags/lua-resty-jwt   # classic token, scopes user:email + read:org only
   ```
6. Merge to `master`.

## 2. Tag and release

```sh
git checkout master && git pull --ff-only
git tag -a vX.Y.Z -m "vX.Y.Z"          # on the merged master commit
git push origin vX.Y.Z
gh release create vX.Y.Z --verify-tag --title vX.Y.Z --notes-file NOTES.md
```

- `publish.yml` triggers on `release: published`. That fires when you create
  a non-draft release, or when you publish a draft. Saving a draft never
  publishes anything, so you can prepare the release as a draft and publish
  it when you are ready.
- **Pre-releases never publish.** The workflow still starts for a published
  pre-release, but every job is skipped (`if: !github.event.release.prerelease`).
  Turning a pre-release into a full release later does *not* fire `published`
  again, so nothing is uploaded then either. To release that version, delete
  the GitHub release (keep the tag) and create a new, non-pre-release one for
  the same tag.

Then watch the Actions run. The job order is `version` → `test` and
`credentials` → `luarocks` → `opm`. If `version`, `test` or `credentials` fails,
nothing is uploaded. OPM runs only after LuaRocks has succeeded, because a
LuaRocks version can be deleted by its owner and an OPM version can't.

## 3. Verify

```sh
docker run --rm --entrypoint=/bin/sh cdbattags/openresty-testsuite:latest -c '
  luarocks install lua-resty-jwt X.Y.Z-1 && luarocks show lua-resty-jwt
  opm get cdbattags/lua-resty-jwt=X.Y.Z && opm list'
```

- <https://luarocks.org/modules/cdbattags/lua-resty-jwt> lists `X.Y.Z-1`,
  and its rockspec has `tag = "vX.Y.Z"`.
- <https://opm.openresty.org/package/cdbattags/lua-resty-jwt/> lists `X.Y.Z`.
  OPM indexes uploads in the background, so it can take a few minutes.

## 4. Publish the security advisories

For each draft at
<https://github.com/cdbattags/lua-resty-jwt/security/advisories>:

1. Set the affected versions to `< X.Y.Z` and the patched version to `X.Y.Z`.
2. Check the credits.
3. Request a CVE if wanted.
4. Publish.

Do this only once both packages are live.

## If something goes wrong

- **`version` or `test` failed:** nothing was uploaded. Delete the GitHub
  release and the tag (`git push origin :refs/tags/vX.Y.Z`), fix the problem
  on master, then tag and release again.
- **One upload failed and the other succeeded:** fix the cause (for example,
  expired secrets), then use "Re-run failed jobs" on the same run. Both
  servers reject a duplicate version, so nothing can be published twice.
- **A broken package is live.** Never move or reuse a published tag.
  - **LuaRocks:** if only the rockspec is wrong, upload a revision built from
    the same tag:
    `luarocks new_version lua-resty-jwt-X.Y.Z-1.rockspec X.Y.Z-2 --tag=vX.Y.Z`,
    then `luarocks upload lua-resty-jwt-X.Y.Z-2.rockspec --api-key=…`.
    If the code is wrong, release `X.Y.(Z+1)`. Module owners can delete a
    version at `https://luarocks.org/delete/cdbattags/lua-resty-jwt/X.Y.Z-1`,
    but deletion is irreversible and mirrors may keep a copy, so keep it for
    releases that are actually dangerous.
  - **OPM:** you can't delete a single version, and re-uploading the same
    version is rejected as a duplicate upload. The server's only delete
    action removes the *whole* `cdbattags/lua-resty-jwt` package (every
    version) after a 3-day grace period, so don't use it. Release
    `X.Y.(Z+1)` instead.
