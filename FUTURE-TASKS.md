# Future tasks

## Optional screening stage for the AGW

Add a screening agent only as an advisory stage before the deterministic AGW
dispatcher:

```text
request -> immutable scope/policy checks -> screening decision -> AGW dispatcher -> reviewed tool
```

The screening agent may explain or reject requests based on engagement context,
but it must not receive process execution access, alter `AGW_ALLOWED_TARGETS`,
change the capability registry, or replace deterministic scope and tool-policy
checks. Its decisions and the subsequent policy outcome must be audit logged.
