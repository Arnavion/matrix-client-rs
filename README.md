TUI [Matrix](https://matrix.org/) client in Rust.


# Features

- `tmux` windows for rooms.
- Read-only.
- No E2EE support. Use something like [pantalaimon.](https://github.com/matrix-org/pantalaimon)


# Dependencies

- `tmux` - The TUI framework.
- `/etc/machine-id` - Used to derive the device ID when logging in.


# Usage

1. Build:

   ```sh
   cargo build --release
   ```

1. Run:

   ```sh
   ./target/release/matrix-client <user_id>
   ```

   Example:

   ```sh
   ./target/release/matrix-client '@arnavion:arnavion.dev'
   ```

   If you want to use a proxy like [pantalaimon](https://github.com/matrix-org/pantalaimon) intead of connecting directly to the homeserver, set the `MATRIX_HOMESERVER_BASE_URL` env var.

   Example:

   ```sh
   MATRIX_HOMESERVER_BASE_URL='http://[::1]:8009' ./target/release/matrix-client '@arnavion:arnavion.dev'
   ```

1. Import E2E keys backup from Element:

   ```sh
   ./target/release/matrix-client <user_id> config import-e2e-keys-backup ~/Downloads/element.keys.txt
   ```


# TODO

- Send events.
- Mark events as read on homeserver.
- Update events for redactions and replace.
- Custom mouse events to support scrolling into prev batch.


# License

AGPL-3.0-only

```
matrix-client-rs

https://github.com/Arnavion/matrix-client-rs

Copyright 2021 Arnav Singh

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, version 3 of the
License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```
