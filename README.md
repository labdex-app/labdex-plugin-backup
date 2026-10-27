# Backup

A [labdex](https://github.com/reykimedev/labdex) plugin. Scheduled backups of the database and inventory to a folder (local disk or a mounted NFS share) or an S3 bucket, encrypted with a passphrase. Secrets in a backup stay encrypted with secret.key, which is never included.

**Version** 1.2 · **Works with** labdex >=1.3,<2 · **Plugin id** `backup`

> [!WARNING]
> Built with AI, for home labs only: labdex and its plugins were written largely with an AI
> coding assistant (Claude), directed and reviewed by a human. They haven't had an independent
> security audit and may contain security problems. Run them on a trusted home network.

## Install

It ships with labdex: **Plugins › Marketplace**, then *Install* (nothing is downloaded). Updates arrive through the official Marketplace (signed with the labdex project key).

## Settings

| Setting | Notes |
| --- | --- |
| Where to |  |
| Folder | Empty = backups/ in labdex's data folder. For NFS, mount the share into the container and give that path. |
| S3 endpoint | e.g. https://s3.eu-central-1.amazonaws.com or your MinIO / Garage URL |
| S3 bucket |  |
| S3 region |  |
| S3 key prefix |  |
| S3 access key |  |
| S3 secret key |  |
| Encryption passphrase | Strongly recommended, required for S3. Without it the backup can't be restored, so store it in your password manager. |
| Keep the newest … |  |

## Actions

- **Back up now** (run)
- **Download a fresh backup** (export)

## Releasing

Bump `version` in `plugin.yaml`, add a `## <version>` section to `CHANGELOG.md`, commit, then
publish a GitHub release tagged `v<version>` (web UI, or `gh release create v<version> --target main --notes ""`).
The release workflow signs the plugin with the `LABDEX_SIGNING_KEY` secret, attaches the zip and
`CHANGELOG.md` to the release and puts that version's CHANGELOG section into its description.
Files listed in `.releaseignore` stay out of the zip.
