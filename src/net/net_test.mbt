// The only IO in the repo: a toy client and a toy server talking over a
// real loopback socket (docs/07 layer 3 warm-up, before OpenSSH).

///|
async test "loopback: client and server complete kex and exchange a service request" {
  let log : Array[String] = []
  @async.with_task_group() <| root => {
    let server = @socket.TcpServer(@socket.Addr::parse("127.0.0.1:0"))
    let addr = server.addr
    root.spawn_bg() <| () => {
      defer server.close()
      let (conn, _) = server.accept()
      defer conn.close()
      let seed = @net.random_bytes(32)
      let t = @transport.Transport::new(@net.server_config(host_seed=seed))
      @net.run(conn, t, (t, ev) => {
        match ev {
          Established(session_id~) =>
            log.push("server established \{session_id.length()}")
          Packet(payload~) => {
            let service = @transport.decode_service_request(payload[:]) catch {
              _ => {
                log.push("server: unexpected packet")
                return
              }
            }
            log.push("server got service request \{service}")
            t.send_packet(@transport.encode_service_accept(service)[:])
          }
          Disconnect(code~, description~, by_peer~) =>
            log.push("server disconnect \{code} \{description} \{by_peer}")
        }
      })
    }
    let client = root.spawn(() => {
      let conn = @socket.Tcp::connect(addr)
      defer conn.close()
      let t = @transport.Transport::new(
        @net.client_config(accept_host_key=_ => true),
      )
      @net.run(conn, t, (t, ev) => {
        match ev {
          Established(session_id~) => {
            log.push("client established \{session_id.length()}")
            t.send_packet(
              @transport.encode_service_request(@transport.SERVICE_USERAUTH)[:],
            )
          }
          Packet(payload~) => {
            let service = @transport.decode_service_accept(payload[:]) catch {
              _ => {
                log.push("client: unexpected packet")
                return
              }
            }
            log.push("client got service accept \{service}")
            t.disconnect(@transport.SSH_DISCONNECT_BY_APPLICATION, "done")
          }
          Disconnect(code~, description~, by_peer~) =>
            log.push("client disconnect \{code} \{description} \{by_peer}")
        }
      })
      t.session_id()
    })
    ignore(client.wait())
  }
  // Event order across the two tasks is not deterministic; check the set.
  assert_eq(log.length(), 5)
  for
    want in [
      "client established 32", "client got service accept ssh-userauth", "server disconnect 11 done true",
      "server established 32", "server got service request ssh-userauth",
    ] {
    assert_true(log.contains(want))
  }
}

///|
async test "random_bytes returns the requested length and is not constant" {
  let a = @net.random_bytes(32)
  let b = @net.random_bytes(32)
  assert_eq(a.length(), 32)
  assert_eq(b.length(), 32)
  assert_not_eq(a, b)
}
