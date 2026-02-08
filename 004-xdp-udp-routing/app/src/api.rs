use axum::{
    Router,
    extract::{Path, State},
    routing::get,
};
use aya::{
    Ebpf,
    maps::{Array, HashMap, MapData},
};
use log::{info, warn};
use poc_common::{GlobalRule, HalfRoute, Policy};
use serde::Deserialize;
use std::{
    fmt::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::{net::TcpListener, sync::Mutex};

#[derive(Clone)]
struct Context {
    ebpf: Arc<Mutex<Ebpf>>,
}

pub async fn run(ebpf: Ebpf, bind: String) {
    let state = Context {
        ebpf: Arc::new(Mutex::new(ebpf)),
    };

    let app = Router::new()
        .route("/policy/{policy}", get(policy_handler))
        .route("/mirror/list", get(mirror_list_handler))
        .route("/mirror/add/{port}", get(mirror_add_handler))
        .route("/mirror/remove/{port}", get(mirror_remove_handler))
        .route("/route/list", get(route_list_handler))
        .route(
            "/route/add/{src}/{sport}/{dst}/{dport}",
            get(route_add_handler),
        )
        .route(
            "/route/remove/{srt}/{sport}/{dst}/{dport}",
            get(route_remove_handler),
        )
        .with_state(state);

    let listener = TcpListener::bind(bind).await.expect("bind");
    info!("* API: http://{}", listener.local_addr().expect("addr"));

    axum::serve(listener, app).await.expect("api");
}

async fn policy_handler(policy: Path<String>, State(state): State<Context>) -> String {
    let Path(policy) = policy;
    let policy = match policy.as_str() {
        "accept" => Policy::Accept,
        "drop" => Policy::Drop,
        _ => return "Error: Bad policy".to_owned(),
    };

    let mut bpf = state.ebpf.lock().await;
    let mut globals: Array<&mut MapData, u8> =
        Array::try_from(bpf.map_mut("XDP_ROUTER_GLOBAL").expect("map")).expect("map");
    let res = globals.set(GlobalRule::Policy as u32, policy as u8, 0);

    info!("Policy changed: {policy:?}");
    format!("{res:?}")
}

async fn mirror_add_handler(port: Path<u16>, State(state): State<Context>) -> String {
    let Path(port) = port;

    let mut bpf = state.ebpf.lock().await;
    let mut mirrors: HashMap<&mut MapData, u16, u8> =
        HashMap::try_from(bpf.map_mut("XDP_ROUTER_MIRRORS").expect("map")).expect("map");

    if mirrors.get(&port.to_be(), 0).is_ok() {
        return "Error: Already exist".to_owned();
    }

    mirrors.insert(port.to_be(), 1u8, 0).expect("map-insert"); // SAFETY: no concurency expected

    info!("Mirror added {port}");
    "OK\n".to_owned()
}

async fn mirror_remove_handler(port: Path<u16>, State(state): State<Context>) -> String {
    let Path(port) = port;

    let mut bpf = state.ebpf.lock().await;
    let mut mirrors: HashMap<&mut MapData, u16, u8> =
        HashMap::try_from(bpf.map_mut("XDP_ROUTER_MIRRORS").expect("map")).expect("map");

    if mirrors.get(&port.to_be(), 0).is_err() {
        return "Error: Does not exist".to_owned();
    }

    mirrors.remove(&port.to_be()).expect("map-remove"); // SAFETY: no concurency expected

    info!("Mirror removed {port}");
    "OK\n".to_owned()
}

async fn mirror_list_handler(State(state): State<Context>) -> String {
    info!("API: List mirror ports");

    let bpf = state.ebpf.lock().await;
    let mirrors: HashMap<&MapData, u16, u8> =
        HashMap::try_from(bpf.map("XDP_ROUTER_MIRRORS").expect("map")).expect("map");

    let mut ret = String::new();
    for port in mirrors.iter() {
        match port {
            Ok((port, _)) => ret += &format!("{}\n", u16::from_be(port)),
            Err(e) => ret += &format!("Error {e:?}\n"),
        }
    }
    info!("{ret}");
    ret
}

async fn route_add_handler(
    route: Path<(SocketAddr, u16, SocketAddr, u16)>,
    State(state): State<Context>,
) -> String {
    let Path((src, sport, dst, dport)) = route;

    let IpAddr::V4(saddr) = src.ip() else {
        return "Error: IPv6 not supported".to_owned();
    };
    let IpAddr::V4(daddr) = dst.ip() else {
        return "Error: IPv6 not supported".to_owned();
    };

    let half1 = HalfRoute {
        reflexive_addr: saddr.into(),
        reflexive_port: src.port(),
        router_port: sport,
    }
    .to_be();

    let half2 = HalfRoute {
        reflexive_addr: daddr.into(),
        reflexive_port: dst.port(),
        router_port: dport,
    }
    .to_be();

    let mut bpf = state.ebpf.lock().await;
    let mut routes: HashMap<&mut MapData, HalfRoute, HalfRoute> =
        HashMap::try_from(bpf.map_mut("XDP_ROUTER_ROUTES").expect("map")).expect("map");

    if routes.get(&half1, 0).is_ok() {
        return "Error: Already exist".to_owned();
    }
    if routes.get(&half2, 0).is_ok() {
        return "Error: Should not happen".to_owned();
    }

    routes.insert(half1, half2, 0).expect("h1"); // SAFETY: no concurency expected
    routes.insert(half2, half1, 0).expect("h2");

    info!("Route added: {src} -> [ {sport} == {dport} ] -> {dst}");
    "OK\n".to_owned()
}

async fn route_remove_handler(
    route: Path<(SocketAddr, u16, SocketAddr, u16)>,
    State(state): State<Context>,
) -> String {
    let Path((src, sport, dst, dport)) = route;

    let IpAddr::V4(saddr) = src.ip() else {
        return "Error: IPv6 not supported".to_owned();
    };
    let IpAddr::V4(daddr) = dst.ip() else {
        return "Error: IPv6 not supported".to_owned();
    };

    let half1 = HalfRoute {
        reflexive_addr: saddr.into(),
        reflexive_port: src.port(),
        router_port: sport,
    }
    .to_be();

    let half2 = HalfRoute {
        reflexive_addr: daddr.into(),
        reflexive_port: dst.port(),
        router_port: dport,
    }
    .to_be();

    let mut bpf = state.ebpf.lock().await;
    let mut routes: HashMap<&mut MapData, HalfRoute, HalfRoute> =
        HashMap::try_from(bpf.map_mut("XDP_ROUTER_ROUTES").expect("map")).expect("map");

    if routes.get(&half1, 0).is_err() {
        return "Error: Does not exist".to_owned();
    }
    if routes.get(&half2, 0).is_err() {
        return "Error: Should not happen".to_owned();
    }

    routes.remove(&half1).expect("h1"); // SAFETY: no concurency expected
    routes.remove(&half2).expect("h2");

    info!("Route removed: {src} -> [ {sport} == {dport} ] -> {dst}");
    "OK\n".to_owned()
}

async fn route_list_handler(State(state): State<Context>) -> String {
    info!("API: List routes");

    let bpf = state.ebpf.lock().await;
    let routes: HashMap<&MapData, HalfRoute, HalfRoute> =
        HashMap::try_from(bpf.map("XDP_ROUTER_ROUTES").expect("map")).expect("map");

    let mut ret = String::new();
    for route in routes.iter() {
        match route {
            Ok((h1, h2)) => ret += &format!("{:?}->{:?}\n", h1.from_be(), h2.from_be()),
            Err(e) => ret += &format!("Error {e:?}\n"),
        }
    }
    info!("{ret}");
    ret
}
