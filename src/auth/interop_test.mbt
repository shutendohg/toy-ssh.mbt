// In-memory client <-> server userauth: docs/06 M3 acceptance 1.

///|
/// Pass payloads between the two machines until neither has output.
/// Returns `(client events, server events)` as text, in order.
fn pump(
  c : @auth.AuthClient,
  s : @auth.AuthServer,
) -> (Array[String], Array[String]) {
  let ce : Array[String] = []
  let se : Array[String] = []
  for _ in 0..<20 {
    let from_client = c.take_outgoing()
    let from_server = s.take_outgoing()
    if from_client.length() == 0 && from_server.length() == 0 {
      break
    }
    for payload in from_client {
      for e in s.on_payload(payload[:]) {
        se.push(Repr(e).to_string())
      }
    }
    for payload in from_server {
      for e in c.on_payload(payload[:]) {
        ce.push(Repr(e).to_string())
      }
    }
  }
  (ce, se)
}

///|
test "interop: the correct password authenticates" {
  let c = test_client(probe_none=true, password=Some("hunter2"))
  let s = test_server()
  let (ce, _) = pump(c, s)
  assert_true(ce[ce.length() - 1] == "Success")
  assert_true(c.is_authenticated())
  debug_inspect(s.user(), content="Some(\"alice\")")
}

///|
test "interop: a wrong password fails and the client gives up" {
  let c = test_client(password=Some("wrong"))
  let s = test_server()
  let (ce, _) = pump(c, s)
  assert_true(ce[ce.length() - 1].contains("GiveUp"))
  assert_false(c.is_authenticated())
  assert_false(s.is_authenticated())
}

///|
test "interop: an authorized key authenticates through query then signature" {
  let c = test_client(key=Some(key_pair()))
  let s = test_server()
  let (ce, se) = pump(c, s)
  debug_inspect(ce, content="[\"Success\"]")
  assert_true(c.is_authenticated())
  assert_true(s.is_authenticated())
  // The server saw the query form and then the authentication form.
  assert_eq(se.length(), 3)
  assert_true(se[0].contains("PublicKeyQuery"))
  assert_true(se[1].contains("PublicKeySigned"))
  assert_true(se[2] == "Authenticated(user=\"alice\")")
  assert_eq(s.failure_count(), 0)
}

///|
test "interop: an authorized key also works without the query phase" {
  let c = test_client(key=Some(key_pair()), query_first=false)
  let s = test_server()
  let (ce, _) = pump(c, s)
  debug_inspect(ce, content="[\"Success\"]")
}

///|
test "interop: an unauthorized key fails, then the password succeeds" {
  let c = test_client(key=Some(other_pair()), password=Some("hunter2"))
  let s = test_server()
  let (ce, _) = pump(c, s)
  assert_true(ce[0].contains("Failure"))
  assert_true(ce[ce.length() - 1] == "Success")
  assert_eq(s.failure_count(), 1)
}

///|
test "interop: an unauthorized key alone gives up" {
  let c = test_client(key=Some(other_pair()))
  let s = test_server()
  let (ce, _) = pump(c, s)
  assert_true(ce[ce.length() - 1].contains("GiveUp"))
  assert_false(s.is_authenticated())
}

///|
test "interop: the banner reaches the client before the outcome" {
  let c = test_client(password=Some("hunter2"))
  let s = test_server(banner=Some("toy-ssh: do not use for real security\n"))
  let (ce, _) = pump(c, s)
  assert_true(ce[0].contains("Banner"))
  assert_true(ce[ce.length() - 1] == "Success")
}
