(module
  (import "env" "call_http" (func $call_http (param i32 i32 i32 i32)))
  (import "env" "set_output" (func $set_output (param i32 i32)))
  (memory (export "memory") 1)
  ;; JSON at offset 64; length is 60
  (data (i32.const 64) "{\"method\":\"POST\",\"url\":\"http://example.com/api\",\"body\":\"{}\"}")
  (func (export "run")
    (local $len i32)
    ;; call_http(ptr=64, len=60, out_ptr=1024, reserved=0)
    i32.const 64
    i32.const 60
    i32.const 1024
    i32.const 0
    call $call_http

    ;; load returned length from [1024..1028]
    i32.const 1024
    i32.load
    local.set $len

    ;; forward bytes to set_output
    i32.const 1028
    local.get $len
    call $set_output))