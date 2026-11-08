# Exact filesystem evidence

Nine fixed scenarios x three modes = 27 observations. No model or detector ran.

READ means the original reader returned exact bytes `NOTE-MARKER` plus LF.
Rejection and NOT_FOUND have no returned bytes. These are fixture counts, not attack rates.

| Scenario | v1.3.1 | v1.3.2 | New guard, eager caller |
|---|---|---|---|
| regular | READ | READ | READ |
| relative_leaf | READ | GUARD_REJECTED | READ |
| absolute_leaf | READ | GUARD_REJECTED | READ |
| chained_leaf | READ | GUARD_REJECTED | READ |
| dangling_leaf | NOT_FOUND | NOT_FOUND | NOT_FOUND |
| parent_link | READ | READ | READ |
| sensitive_name | GUARD_REJECTED | GUARD_REJECTED | GUARD_REJECTED |
| secret_env | READ | GUARD_REJECTED | GUARD_REJECTED |
| missing | NOT_FOUND | NOT_FOUND | NOT_FOUND |

## Exact leaf-link trace

`relative.txt -> data/note.txt`, whose bytes are hex `4e4f54452d4d41524b45520a`.

- **before**: supplied(relative.txt, leaf_link=true) -> resolve_before_guard(data/note.txt, leaf_link=false) -> guard_input(data/note.txt, leaf_link=false) -> read_input(data/note.txt, leaf_link=false) -> READ.
- **after**: supplied(relative.txt, leaf_link=true) -> guard_input(relative.txt, leaf_link=true) -> GUARD_REJECTED.
- **after_guard_eager_caller**: supplied(relative.txt, leaf_link=true) -> resolve_before_guard(data/note.txt, leaf_link=false) -> guard_input(data/note.txt, leaf_link=false) -> read_input(data/note.txt, leaf_link=false) -> READ.

The eager-caller counterfactual shows the new guard cannot reject a link already resolved away.
Both actual revisions read through a linked parent directory. The patch is not a complete no-follow boundary.
secret.env differs because v1.3.2 separately adds *.env to the sensitive-name list.
Dangling and missing paths fail the caller's is_file check before the guard.
No concurrency, link swap, Windows junction, scanner verdict or live agent behavior is tested.
