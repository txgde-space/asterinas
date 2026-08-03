# Stage 09D — IPv4 raw `sendmsg` ancillary options

This stage extends the IPv4 raw-socket ABI without changing the existing
socket-level option behavior:

- `SOL_IP/IP_TTL` and `SOL_IP/IP_TOS` control messages are decoded from
  `sendmsg(2)` ancillary data;
- the values override the socket defaults for that one packet;
- `IP_HDRINCL` remains authoritative when the caller supplies an IPv4 header;
- malformed or out-of-range integer payloads return `EINVAL`;
- the regression suite verifies the emitted IPv4 TTL and TOS on loopback.

`IP_RECVERR` is intentionally not included here.  The option get/set ABI
already exists, but a real `MSG_ERRQUEUE` implementation needs a separate
error-queue lifecycle and will be delivered as the next raw-socket stage.

Ubuntu verification command:

```sh
AUTO_TEST=regression CONSOLE=ttyS0 LOG_LEVEL=error ENABLE_KVM=1 SMP=4 RELEASE=1 make run_kernel
```

Record the complete output as `stage-records/stage-09d/regression.log` and
archive it with the other stage records after the run passes.
