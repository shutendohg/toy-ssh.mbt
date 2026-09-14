///|
/// Toy SSH server, M2 scope: accepts a connection, completes the key
/// exchange, answers SERVICE_REQUEST ssh-userauth with SERVICE_ACCEPT,
/// and then disconnects because user authentication is M3.
///
/// Usage: server [--listen 127.0.0.1:2222] [--host-seed-hex <64 hex>]
///
/// Toy code. Never use for real security.

///|
async fn main {
  let args = @env.args()
  let mut listen = "127.0.0.1:2222"
  let mut seed_hex : String? = None
  let mut i = 1
  while i < args.length() {
    match args[i] {
      "--listen" => {
        guard i + 1 < args.length() else {
          println("--listen needs a value")
          @sys.exit(2)
        }
        listen = args[i + 1]
        i = i + 2
      }
      "--host-seed-hex" => {
        guard i + 1 < args.length() else {
          println("--host-seed-hex needs a value")
          @sys.exit(2)
        }
        seed_hex = Some(args[i + 1])
        i = i + 2
      }
      other => {
        println("unknown argument: \{other}")
        @sys.exit(2)
      }
    }
  }
  let seed = match seed_hex {
    Some(h) =>
      @hex.decode(h) catch {
        _ => {
          println("--host-seed-hex must be 64 hex digits")
          @sys.exit(2)
          b""
        }
      }
    None => @net.random_bytes(32)
  }
  println("toy-ssh server: host key seed \{@hex.encode(seed[:])}")
  let server = @socket.TcpServer(@socket.Addr::parse(listen), reuse_addr=true)
  println("toy-ssh server: listening on \{server.addr}")
  server.run_forever(allow_failure=true) <| ((conn, peer) => {
    defer conn.close()
    println("[\{peer}] connected")
    let t = @transport.Transport::new(@net.server_config(host_seed=seed))
    @net.run(conn, t, (t, ev) => {
      match ev {
        Established(session_id~) =>
          println(
            "[\{peer}] established, session id \{@hex.encode(session_id[:])}",
          )
        Packet(payload~) => handle_packet(t, peer, payload)
        Disconnect(code~, description~, by_peer~) =>
          println(
            "[\{peer}] disconnect code=\{code} \"\{description}\" by_peer=\{by_peer}",
          )
      }
    })
    println("[\{peer}] closed")
  })
}

///|
fn handle_packet(
  t : @transport.Transport,
  peer : @socket.Addr,
  payload : Bytes,
) -> Unit {
  if payload.length() > 0 && payload[0] == @transport.SSH_MSG_SERVICE_REQUEST {
    let service = @transport.decode_service_request(payload[:]) catch {
      _ => ""
    }
    if service == @transport.SERVICE_USERAUTH {
      println("[\{peer}] service request \{service}: accepted")
      t.send_packet(@transport.encode_service_accept(service)[:])
      return
    }
    if service != "" {
      println("[\{peer}] service request \{service}: refused")
      t.disconnect(
        @transport.SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
        "service not available",
      )
      return
    }
  }
  println(
    "[\{peer}] message \{payload[0].to_int()} after kex: userauth is M3, disconnecting",
  )
  t.disconnect(
    @transport.SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
    "toy-ssh: user authentication is not implemented yet (M3)",
  )
}
