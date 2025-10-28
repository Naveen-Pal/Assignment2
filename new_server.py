import socket
import json
import datetime
import time
import pandas as pd
import dns.message
import dns.rcode
import dns.rdatatype
import dns.flags
import dns.query
from dns.exception import DNSException, Timeout


INTER_PACKET_SLEEP = 0.0

# UDP Server Setup
HOST = '10.0.0.5'   # Localhost
PORT = 53          # Listening port (same as client uses)

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))
print(f"Server running on {HOST}:{PORT}")

ROOT_SERVERS = [
    "10.0.136.8",
    "8.8.8.8",
]

dns_cache = {}
dns_cache['response_cache'] = {}
failure = 0
success = 0

count = 0
total_time = 0
logs = []
client_ip = ""
total_bytes = 0




df = pd.DataFrame(columns=[
    "Timestamp",'Client IP', "Domain", "Mode", "Server_IP", "Step",
    "Response type", "RTT(s)", "Cache Status", "Cumulative Time(ms)","Cumulative Bytes"
])

with open('dns_logs.csv', 'w', newline='') as f:
    f.write("Timestamp,Client IP,Domain,Mode,Server_IP,Step,Response type,RTT(s),Cache Status,Cumulative Time(ms),Cumulative Bytes\n")

def log_event(domain, mode, server_ip, step, response_type, rtt, cache_status):
    global df
    global total_time
    global total_bytes

    with open('dns_logs.csv', 'a', newline='') as f:
        f.write(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')},{client_ip},{domain},{mode},{server_ip},{step},{response_type},{round(rtt, 4) if rtt else None},{cache_status},{round(total_time, 4)},{total_bytes}\n")

    # new_row = pd.DataFrame([{
    #     "Timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    #     "Client IP":client_ip,
    #     "Domain": domain,
    #     "Mode": mode,
    #     "Server_IP": server_ip,
    #     "Step": step,
    #     "Response type": response_type,
    #     "RTT(s)": round(rtt, 4) if rtt else None,
    #     "Cache Status": cache_status,
    #     "Cumulative Time(ms)": round(total_time, 4)
    # }])
    # df = pd.concat([df, new_row], ignore_index=True)

    

# Convert HH:MM → minutes since midnight
def parse_time(timestr):
    h, m = map(int, timestr.split(":"))
    return h * 60 + m


def update_cache(response: dns.message.Message, dns_cache):
    """
    Update cache with intermediate results
    """
    domain_name = response.authority[0].to_text().split(" ")[0]

    arecords = []
    rrsets = response.additional

    # Traverse in all resource records of A type
    for rrset in rrsets:
        for rr_ in rrset:
            if rr_.rdtype == dns.rdatatype.A:
                arecords.append(str(rr_))
                dns_cache[domain_name] = str(rr_)
    # print(f"Updated cache with {domain_name} : {arecords}")

def lookup(target_name: dns.name.Name,
           qtype: dns.rdata.Rdata,
           dns_cache: dict) -> dns.message.Message:
    global total_time
    global count
    global total_bytes
    i = 0
    resolved = False

    cache_tries = 0
    while i < len(ROOT_SERVERS):
        ip_from_cache = ""
        find_name = str(target_name)
        next_dot = str(target_name).find('.')

        # Check cache for longest suffix match
        while not ip_from_cache and next_dot > -1:
            ip_from_cache = dns_cache.get(find_name)
            find_name = str(find_name)[next_dot+1:]
            next_dot = find_name.find('.')

        # If there is a cached IP, start from there
        if ip_from_cache:
            ip_ = ip_from_cache
            step_type = "Authoritative"
            log_event(str(target_name), "Recursive", "-", "Cache", "Referral", 0, "HIT")
            cache_tries += 1
            if cache_tries > 1:
                dns_cache.pop(find_name, None)
                ip_ = ROOT_SERVERS[i]
                step_type = "Root"

        else:
            ip_ = ROOT_SERVERS[i]
            step_type = "Root"

        try:
            response, resolved = lookup_recurse(target_name, qtype, ip_, resolved, dns_cache, step_type)

            if response.answer:
                return response
            elif response.authority and response.authority[0].rdtype == dns.rdatatype.SOA:
                break
            else:
                i += 1
        except Timeout:
            i += 1
        except DNSException:
            i += 1                      

    return response # failure

def lookup_recurse(target_name: dns.name.Name,
                   qtype: dns.rdata.Rdata,
                   ip_,
                   resolved,
                   dns_cache: dict, step_type) -> dns.message.Message:
    """
    This function uses a recursive resolver to find the relevant answer to the
    query,
    """
    global total_time
    global count
    global total_bytes

    # Make DNS query
    outbound_query = dns.message.make_query(target_name, qtype)
    total_bytes += len(outbound_query.to_wire())

    # Determine next step type
    next_step = "Authoritative"

    if step_type == "Root":
        next_step = "TLD"
    
    result_type = ""
    try:
        # Send dns query using UDP and measure RTT
        start = time.monotonic()
        response = dns.query.udp(outbound_query, ip_, 3)
        rtt = (time.monotonic() - start) * 1000.0
        count += 1
        total_time += rtt

        # bytes received (response)
        total_bytes += len(response.to_wire())

        if response.answer:
            resolved = True             
            result_type = "Response" 
            log_event(str(target_name), "Recursive", ip_ , step_type, "Response", rtt, "MISS")
            return response, resolved
        elif response.additional:
            result_type = "Referral"
            # Update cache with any A records in additional section
            if response.authority:
                update_cache(response, dns_cache)
            log_event(str(target_name), "Recursive", ip_, step_type, result_type, rtt, "MISS")
            response, resolved = lookup_additional(response, target_name,
                                                   qtype, resolved, dns_cache, next_step)

        elif response.authority and not resolved:
            result_type = "Referral"
            log_event(str(target_name), "Recursive", ip_, step_type, result_type, rtt, "MISS")
            response, resolved = lookup_authority(response, target_name,
                                                  qtype, resolved, dns_cache, next_step)
        return response, resolved

    except Timeout:
        return dns.message.Message(), False
    except DNSException:
        return dns.message.Message(), False
    
def lookup_additional(response,
                      target_name: dns.name.Name,
                      qtype: dns.rdata.Rdata,
                      resolved,
                      dns_cache: dict, step_type) -> dns.message.Message:
    """
    Recursively lookup additional
    """
    rrsets = response.additional
    for rrset in rrsets:
        for rr_ in rrset:
            if rr_.rdtype == dns.rdatatype.A:
                response, resolved = lookup_recurse(target_name, qtype,
                                                    str(rr_), resolved, dns_cache, step_type)
            if resolved:
                break
        if resolved:
            break
    return response, resolved
    
def lookup_authority(response,
                     target_name: dns.name.Name,
                     qtype: dns.rdata.Rdata,
                     resolved,
                     dns_cache: dict,step_type):
    """
    Recursively lookup authority
    """                  
    rrsets = response.authority
    ns_ip = ""
    for rrset in rrsets:
        for rr_ in rrset:
            if rr_.rdtype == dns.rdatatype.NS:
                ns_ip = dns_cache.get(str(rr_))
                if not ns_ip:
                    # Need to lookup for NS IP, since its not present in additional section
                    ns_arecords = lookup(str(rr_), dns.rdatatype.A, dns_cache)
                    if ns_arecords.answer and len(ns_arecords.answer[0]) > 0:
                        ns_ip = str(ns_arecords.answer[0][0])
                    else:
                        continue
                    dns_cache[str(rr_)] = ns_ip

                response, resolved = lookup_recurse(target_name, qtype,
                                                    ns_ip, resolved, dns_cache,step_type)
            elif rr_.rdtype == dns.rdatatype.SOA:
                resolved = True
                break
        if resolved:
            break

    return response, resolved

# def print_logs():
    # print("\n\n=== DNS Resolution Log ===")
    # for entry in logs:
        # print(" | ".join(f"{k}: {v}" for k, v in entry.items()))


temp_dict = dict()

while True:
    total_time = 0
    total_bytes = 0
    with open("dc_suc_fail.json", "w") as f:
        json.dump({str(k): v for k, v in temp_dict.items()}, f, indent=2)
    try:
        data, addr = sock.recvfrom(4096)   # bytes from client
        client_ip, client_port = addr

        if client_ip not in temp_dict.keys():
            temp_dict[client_ip] = {"success":0,"failure":0}

        # Parse incoming DNS request using dnspython
        try:
            dns_req = dns.message.from_wire(data)

        except Exception as e:
            # malformed packet — ignore or optionally log
            print(f"Bad DNS packet from {client_ip}:{client_port} — {e}")
            continue
        
        # check if the request is for recursive resolution
        if not (dns_req.flags & dns.flags.RD):
            # Build a minimal REFUSED response
            response_msg = dns.message.Message(id=dns_req.id)
            response_msg.flags |= dns.flags.QR        # It's a response
            response_msg.flags &= ~dns.flags.AA       # Not authoritative
            response_msg.flags |= dns.flags.RA        # Recursion available (but not used)
            response_msg.set_rcode(dns.rcode.REFUSED)
            sock.sendto(response_msg.to_wire(), addr)
            log_event(domain_name, "Not Recursive", "-", "N/A", "Failure", 0, "MISS")
            continue
        # otherwiser do the recursive resolution

        # Ensure there is at least one question
        if not dns_req.question:
            # nothing to do, ignore
            continue

        q = dns_req.question[0]
        domain_name = q.name.to_text()
        qtype = q.rdtype 

        # Check cache (store cached responses as bytes to avoid mutability issues)
        cache_store = dns_cache.get('response_cache', {})
        cached_wire = cache_store.get(domain_name)

        if cached_wire:
            # Cache HIT: recreate message from bytes and patch the request ID
            try:
                cached_msg = dns.message.from_wire(cached_wire)

                # Preserve requester transaction id
                cached_msg.id = dns_req.id

                # Ensure flags show response
                cached_msg.flags |= dns.flags.QR

                # Not authoritative (resolver)
                cached_msg.flags &= ~dns.flags.AA

                # Preserve client's transaction ID
                cached_msg.id = dns_req.id

                # Copy RD from client
                if dns_req.flags & dns.flags.RD:
                    cached_msg.flags |= dns.flags.RD
                else:
                    cached_msg.flags &= ~dns.flags.RD

                # Set RA = 1 (we support recursion)
                cached_msg.flags |= dns.flags.RA
        
                # Send cached response bytes (use to_wire to ensure proper encoding with patched id)
                out = cached_msg.to_wire()
                sock.sendto(out, addr)

                # Logging similar to your snippet
                log_event(domain_name, "Recursive", "-", "Cache", "Response", 0, "HIT")
                total_bytes = len(out)
                # total_time = 0
                for ans in cached_msg.answer:
                    print(ans)

                success += 1
                temp_dict[client_ip]['success']+=1

            except Exception as e:
                # If cached bytes corrupted, remove from cache and fall through to lookup
                print(f"Corrupt cache entry for {domain_name}: {e}")
                cache_store.pop(domain_name, None)

        else:
            # Cache MISS: perform lookup (user-provided function)
            try:
                # Convert q.name to a dns.name.Name if lookup expects that type
                # Here we assume lookup accepts dns.name.Name and qtype numeric
                target_name = q.name
                response_msg = lookup(target_name, qtype, dns_cache)

                # If lookup failed, create a minimal SERVFAIL response
                if response_msg is None:
                    response_msg = dns.message.Message(id=dns_req.id)
                    response_msg.set_rcode(dns.rcode.SERVFAIL)

                # --- Standard response header setup ---

                # Ensure it's a response
                response_msg.flags |= dns.flags.QR

                # Not authoritative (since this is a resolver, not an authoritative server)
                response_msg.flags &= ~dns.flags.AA

                # Preserve RD (Recursion Desired) from client query
                if dns_req.flags & dns.flags.RD:
                    response_msg.flags |= dns.flags.RD
                else:
                    response_msg.flags &= ~dns.flags.RD

                # Indicate recursion is available (RA = 1)
                response_msg.flags |= dns.flags.RA

                # Preserve transaction ID (in case lookup returns a new message object)
                response_msg.id = dns_req.id

                # If no answers, set NXDOMAIN
                if not response_msg.answer:
                    response_msg.set_rcode(dns.rcode.NXDOMAIN)
                    log_event(str(target_name), "Recursive", "-", "N/A", "Failure", 0, "MISS")
                    failure += 1
                    temp_dict[client_ip]['failure'] += 1

                # Send to client
                out = response_msg.to_wire()
                sock.sendto(out, addr)

                # Save canonical copy to cache (store the wire bytes, not the object)
                dns_cache.setdefault('response_cache', {})[domain_name] = out

                # Print / logging
                for ans in response_msg.answer:
                    print(ans)

                if response_msg.answer:
                    success += 1
                    temp_dict[client_ip]['success']+=1

            except Exception as e:
                # If lookup crashes, reply SERVFAIL to client and log
                print(f"Lookup error for {domain_name}: {e}")
                try:
                    servfail = dns.message.Message(id=dns_req.id)
                    servfail.set_rcode(dns.rcode.SERVFAIL)
                    servfail.flags |= dns.flags.QR
                    sock.sendto(servfail.to_wire(), addr)
                except Exception:
                    pass
                failure += 1
                temp_dict[client_ip]['failure']+=1

        # optional housekeeping and pacing
        time.sleep(INTER_PACKET_SLEEP)

    except KeyboardInterrupt:
        print("Shutting down server loop.")
        break
    except Exception as e:
        # log and continue serving
        print(f"Unexpected server error: {e}")
        continue