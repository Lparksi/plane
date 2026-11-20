# Corresponding Source deployment requirement

The web and admin Help menus and sign-in forms, and the space project navigation
and sign-in form, use the build-time `PLANE_SOURCE_COMMIT` setting. It must be
exactly 40 lowercase hexadecimal characters. The frontend injects only this
specific non-secret variable, then constructs a fixed link to
`https://github.com/Lparksi/plane/tree/<commit>`; arbitrary repositories and
URLs are not accepted. Missing or invalid values display a neutral unavailable
status instead of a link. Rebuild each frontend with the correct value.

**Deployment gate:** make the exact complete source corresponding to every
running component publicly accessible at that commit in `Lparksi/plane` before
exposing the modified service. Do not use the upstream baseline as a substitute
for the final modified release, and do not publish or push without approval.
Record the actual source commit and the image/build identifiers in the release
record; update and verify the binding for every deployment. A syntactically valid
commit alone does not prove the source is public, complete, or matches the
running binaries. Verify the unauthenticated link and compare the published
source with the release. Verify desktop and narrow layouts and provide a
prominent offer for every remote interface, including an independent MCP
endpoint. Follow [LICENSE.txt](../LICENSE.txt), including sections 1, 5, 13, 15,
and 16; a link alone does not establish compliance.

The source must include applicable licenses, notices, build and install scripts,
interface definitions and required dependencies. Include safe example config
files, but never commit real `.env` files, credentials, tokens, private keys,
databases, uploads or other instance data. This change does not publish source
or authorize a deployment.
