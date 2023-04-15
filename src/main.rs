use std::{net::IpAddr, process::Command, thread, time::Duration};

use enigo::*;

use etherparse::{IpHeader, PacketHeaders};
use sysinfo::{PidExt, ProcessExt, ProcessRefreshKind, RefreshKind, System, SystemExt};
use winroute::{Route, RouteManager};

fn get_sot_pid(s: &System) -> Option<u32> {
    for process in s.processes_by_name("SoTGame.exe") {
        return Some(process.pid().as_u32());
    }

    None
}

fn get_sot_ports(pid: u32) -> Vec<u16> {
    let p = &pid.to_string();

    let cmd = Command::new("netstat")
        .arg("-anop")
        .arg("udp")
        .output()
        .unwrap();

    // jarringly, netstat output contains non-utf8 characters :)
    let filtered_stdout = cmd
        .stdout
        .iter()
        .filter(|c| c.is_ascii())
        .copied()
        .collect();

    String::from_utf8(filtered_stdout)
        .unwrap()
        .lines()
        .filter(|line| line.contains(p))
        .map(|f| {
            let addr = f.split_whitespace().skip(1).next().unwrap();
            let port = addr.split(':').last().unwrap();
            port.parse::<u16>().unwrap()
        })
        .collect()
}

fn main() {
    let mut enigo = Enigo::new();
    println!("Soyez sur d'avoir installer Npcap");
    unsafe {
        let try_load_wpcap = libloading::Library::new("wpcap.dll");
        if try_load_wpcap.is_err() {
            println!("{}", "*".repeat(80));
            println!("ERREUR: Vous n'avez pas Npcap");
            println!("Installez Npcap ici:\n    https://npcap.com/dist/npcap-1.72.exe\n");
            println!("*** FAITES ATTENTION A INSTALLER NPCAP AVEC 'WinPcap API Compatibility' ACTIVER ! ***");
            println!("{}\n", "*".repeat(80));
            
            std::process::exit(1);
        }
    }

    // wait until we get a sot pid
    println!("En attente de Sea of Thieves (lancez le jeu)");
    let mut s =
        System::new_with_specifics(RefreshKind::new().with_processes(ProcessRefreshKind::new()));

    let sot_pid = loop {
        if let Some(pid) = get_sot_pid(&s) {
            break pid;
        }
        s.refresh_processes();
    };

    println!("Jeu lancer ! Processus ID: {}", sot_pid);

    let devices = pcap::Device::list().unwrap();
    let auto_found_dev = devices.iter().find(|d| {
        d.addresses.iter().any(|addr| {
            if let IpAddr::V4(addr) = addr.addr {
                addr.octets()[0] == 192 && addr.octets()[1] == 168
            } else {
                false
            }
        })
    });

    let dev = match auto_found_dev {
        Some(d) => d.clone(),
        None => {
            println!("Je ne trouve pas quel adaptateur reseau utiliser, choisissez en un ici");
            println!("Adaptateurs reseaux relies a votre PC: ");

            let devices = pcap::Device::list().expect("device lookup failed");
            let mut i = 1;

            for device in devices.clone() {
                println!(
                    "    {i}. {:?}",
                    device.desc.clone().unwrap_or(device.name.clone())
                );
                i += 1;
            }

            // prompt user for their device
            println!(
                "Selectionnez votre carte WiFi ou Ethernet, si vous avez un VPN choisissez votre VPN: "
            );
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            let n = input.trim().parse::<usize>().unwrap() - 1;

            (&devices[n]).clone()
        }
    };

    let mut cap = pcap::Capture::from_device(dev)
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();

    let route_manager = RouteManager::new().unwrap();
    let the_void = "0.0.0.0".parse().unwrap();

    println!("Sur quel serveur essaye-tu de te connecter ? (e.g. 20.213.146.107:30618)\n    Marque 'aucun' si tu veux juste voir l'ip de ton serveur pour la partager");
    let mut target = String::new(); // ""
    std::io::stdin().read_line(&mut target).unwrap();
    let target = target.trim();

    if target == "aucun" {
        println!("Bien, je marquerais le serveur sur lequel tu te connectes");
    } else {
        println!("Bien, en recherche du serveur: {}", target);
    }

    println!("En attente de connexion, veuillez lever l'ancre !");

    // iterate udp packets
    loop {
        if let Ok(raw_packet) = cap.next_packet() {
            if let Ok(packet) = PacketHeaders::from_ethernet_slice(raw_packet.data) {
                if let Some(IpHeader::Version4(ipv4, _)) = packet.ip {
                    if let Some(transport) = packet.transport {
                        if let Some(udp) = transport.udp() {
                            if udp.destination_port == 3075 || udp.destination_port == 30005 {
                                continue;
                            }

                            if get_sot_ports(sot_pid).contains(&udp.source_port) {
                                let ip = ipv4.destination.map(|c| c.to_string()).join(".");

                                if target == "aucun" {
                                    println!("Tu es connecte sur: {}:{}\n   Tape sur Entrer pour revoir ton serveur", ip, udp.destination_port);
                                    std::io::stdin().read_line(&mut String::new()).unwrap();
                                    continue;
                                }

                                if format!("{}:{}", ip, udp.destination_port) != target {
                                    println!(
                                        "Fail! {}:{}, mauvais serveur.",
                                        ip, udp.destination_port
                                    );
                                } else {
                                    println!("Succes! {}:{}, tu es connecte sur le serveur !", ip, udp.destination_port);
                                    std::io::stdin().read_line(&mut String::new()).unwrap();
                                    break;
                                }

                                let blocking_route =
                                    Route::new(ip.parse().unwrap(), 32).gateway(the_void);

                                // add route
                                if let Err(e) = route_manager.add_route(&blocking_route) {
                                    println!(
                                        "Erreur lor de l'ajout de la route: {}:{} - {}",
                                        ip, udp.destination_port, e
                                    );
                                } else {
                                    // wait for enter
                                    thread::sleep(Duration::from_millis(60*1000));
                                    enigo.key_click(Key::Raw(0x0D));
                                    thread::sleep(Duration::from_millis(5*1000));
                                    enigo.key_click(Key::Escape);
                                    thread::sleep(Duration::from_millis(1000));
                                    //std::io::stdin().read_line(&mut String::new()).unwrap();
                                }

                                println!("Debloquage {}...", ip);

                                // delete route, route_manager.delete_route doesn't work for some reason
                                let status = Command::new("route")
                                    .arg("delete")
                                    .arg(ip)
                                    .status()
                                    .unwrap();
                                if !status.success() {
                                    println!("Impossible de debloquer la route!");
                                }

                                println!("Relancement d'ancre automatique en cours !");
                                thread::sleep(Duration::from_millis(5*1000));
                                enigo.mouse_click(MouseButton::Left);
                                thread::sleep(Duration::from_millis(3*1000));
                                enigo.mouse_click(MouseButton::Left);
                                thread::sleep(Duration::from_millis(3*1000));
                                enigo.mouse_click(MouseButton::Left);
                                thread::sleep(Duration::from_millis(3*1000));
                                enigo.mouse_click(MouseButton::Left);
                                thread::sleep(Duration::from_millis(10*1000));
                                enigo.mouse_click(MouseButton::Left);
                            }
                        }
                    }
                }
            }
        }
    }
}
