# core/utils_red.py
import ipaddress

def ip_externa(ip):
    if not ip:
        return False

    try:
        ip_clean = str(ip).split(":")[0].strip()
        ip_obj = ipaddress.ip_address(ip_clean)
        return not (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_link_local or
            ip_obj.is_unspecified or
            ip_obj.is_reserved or
            ip_obj.is_multicast
        )
    except Exception:
        return False

