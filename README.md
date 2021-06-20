TUI [Matrix](https://matrix.org/) client in Rust.


# Features

- `tmux` windows for rooms.
- Read-only.


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

```
matrix-client-rs

https://github.com/Arnavion/matrix-client-rs

Copyright 2021 Arnav Singh

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
