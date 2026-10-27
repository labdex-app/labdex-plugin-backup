"""Backups to a folder or S3 (SigV4, path-style URLs; works with AWS, MinIO, Garage, Ceph)."""
import datetime as dt
import hashlib
import hmac
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import quote

import requests

from labdex import backup
from labdex.plugins.base import ExportFile, Plugin as Base, PluginError


class S3:
    def __init__(self, endpoint, bucket, region, access_key, secret_key, verify=True):
        if not (endpoint and bucket and access_key and secret_key):
            raise PluginError("S3 needs endpoint, bucket, access key and secret key")
        self.endpoint, self.bucket, self.region = endpoint.rstrip("/"), bucket, region or "us-east-1"
        self.ak, self.sk, self.verify = access_key, secret_key, verify
        self.host = self.endpoint.split("://", 1)[-1]

    def _sign(self, method, key, query: dict, payload: bytes):
        now = dt.datetime.now(dt.UTC)
        amz, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
        path = f"/{self.bucket}/" + quote(key, safe="/-_.~") if key else f"/{self.bucket}"
        qs = "&".join(f"{quote(k, safe='-_.~')}={quote(str(v), safe='-_.~')}" for k, v in sorted(query.items()))
        phash = hashlib.sha256(payload).hexdigest()
        headers = {"host": self.host, "x-amz-content-sha256": phash, "x-amz-date": amz}
        signed = ";".join(sorted(headers))
        canon = "\n".join([method, path, qs, "".join(f"{k}:{headers[k]}\n" for k in sorted(headers)), signed, phash])
        scope = f"{day}/{self.region}/s3/aws4_request"
        sts = "\n".join(["AWS4-HMAC-SHA256", amz, scope, hashlib.sha256(canon.encode()).hexdigest()])
        k = ("AWS4" + self.sk).encode()
        for part in (day, self.region, "s3", "aws4_request"):
            k = hmac.new(k, part.encode(), hashlib.sha256).digest()
        sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
        headers["Authorization"] = f"AWS4-HMAC-SHA256 Credential={self.ak}/{scope}, SignedHeaders={signed}, Signature={sig}"
        return self.endpoint + path + (f"?{qs}" if qs else ""), headers

    def _req(self, method, key="", query=None, data=b""):
        url, headers = self._sign(method, key, query or {}, data)
        try:
            r = requests.request(method, url, headers=headers, data=data or None, timeout=120, verify=self.verify)
        except requests.RequestException as exc:
            raise PluginError(f"S3 {method} failed: {exc}") from exc
        if r.status_code >= 300:
            raise PluginError(f"S3 {method} {key or self.bucket}: HTTP {r.status_code} {r.text[:300]}")
        return r

    def put(self, key, data):
        self._req("PUT", key, data=data)

    def delete(self, key):
        self._req("DELETE", key)

    def list(self, prefix):
        r = self._req("GET", "", {"list-type": "2", "prefix": prefix})
        ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
        root = ET.fromstring(r.content)
        out = []
        for c in root.findall("s3:Contents", ns) or root.findall("Contents"):
            def get(t, c=c):
                found = c.find(f"s3:{t}", ns)
                return (found if found is not None else c.find(t)).text
            out.append({"name": get("Key")[len(prefix):], "size": int(get("Size")), "modified": get("LastModified")})
        return out


class Plugin(Base):
    def _passphrase(self):
        p = self.settings.get("passphrase") or ""
        if self.settings.get("target") == "s3" and not p:
            raise PluginError("set an encryption passphrase before backing up to S3")
        return p

    def _folder(self) -> Path:
        return Path(self.settings.get("path") or (self.ctx.data_dir / "backups"))

    def _s3(self) -> S3:
        s = self.settings
        return S3(s.get("s3_endpoint"), s.get("s3_bucket"), s.get("s3_region"), s.get("s3_access_key"), s.get("s3_secret_key"),
                  verify=s.get("verify_tls", True))

    def _list(self):
        if self.settings.get("target") == "s3":
            items = self._s3().list(self.settings.get("s3_prefix") or "")
        else:
            d = self._folder()
            items = [{"name": p.name, "size": p.stat().st_size,
                      "modified": dt.datetime.fromtimestamp(p.stat().st_mtime, dt.UTC).isoformat()}
                     for p in d.glob(backup.PREFIX + "*")] if d.is_dir() else []
        return sorted((i for i in items if i["name"].startswith(backup.PREFIX)), key=lambda i: i["name"], reverse=True)

    def run_backup(self, params):
        from flask import current_app
        name, data, manifest = backup.create(current_app.config["LABDEX_VERSION"], self._passphrase())
        if self.settings.get("target") == "s3":
            s3, prefix = self._s3(), self.settings.get("s3_prefix") or ""
            s3.put(prefix + name, data)
            where = f"s3://{s3.bucket}/{prefix}{name}"
        else:
            d = self._folder()
            d.mkdir(parents=True, exist_ok=True)
            tmp = d / (name + ".part")
            tmp.write_bytes(data)
            tmp.chmod(0o600)
            tmp.rename(d / name)
            where = str(d / name)
        self.log(f"wrote {where} ({len(data)} bytes{', encrypted' if manifest['encrypted'] else ', NOT encrypted'})")
        removed = self._retention()
        return {"message": f"{name} ({len(data) // 1024} KB){' — not encrypted' if not manifest['encrypted'] else ''}",
                "file": name, "removed": removed}

    def _retention(self) -> int:
        keep = int(self.settings.get("keep") or 14)
        old = self._list()[keep:]
        for item in old:
            if self.settings.get("target") == "s3":
                self._s3().delete((self.settings.get("s3_prefix") or "") + item["name"])
            else:
                (self._folder() / item["name"]).unlink(missing_ok=True)
            self.log(f"removed old backup {item['name']}")
        return len(old)

    def widget_last(self, host):
        items = self._list()
        enc = bool(self.settings.get("passphrase"))
        if not items:
            return {"kind": "stat", "value": "none", "tone": "err", "sub": "no backup yet", "link": f"/integrations/{self.ctx.name}?tab=backups"}
        newest = dt.datetime.fromisoformat(items[0]["modified"].replace("Z", "+00:00"))
        age_h = (dt.datetime.now(dt.UTC) - newest).total_seconds() / 3600
        value, unit = (round(age_h), "h ago") if age_h < 48 else (round(age_h / 24), "d ago")
        tone = "ok" if age_h < 26 else "warn" if age_h < 72 else "err"
        if not enc:
            tone = "warn" if tone == "ok" else tone
        return {"kind": "stat", "value": value, "unit": unit, "tone": tone, "link": f"/integrations/{self.ctx.name}?tab=backups",
                "sub": f"{len(items)} kept · {'encrypted' if enc else 'NOT encrypted'}"}

    def export_download(self, params):
        from flask import current_app
        name, data, _ = backup.create(current_app.config["LABDEX_VERSION"], self.settings.get("passphrase") or "")
        return ExportFile(name, "application/octet-stream", data)

    def endpoint_backups(self, args):
        return self._list()

    def page_backups(self, args):
        items = self._list()
        where = f"s3://{self.settings.get('s3_bucket')}/{self.settings.get('s3_prefix') or ''}" if self.settings.get("target") == "s3" else str(self._folder())
        return {"summary": [{"label": "backups", "value": len(items), "tone": "ok" if items else "warn"},
                            {"label": "encrypted", "value": "yes" if self.settings.get("passphrase") else "NO",
                             "tone": "ok" if self.settings.get("passphrase") else "err"}],
                "sections": [{"title": f"Backups in {where}", "type": "table",
                              "columns": [{"key": "name", "label": "File"}, {"key": "size_kb", "label": "KB"}, {"key": "modified", "label": "Written"}],
                              "rows": [{**i, "size_kb": i["size"] // 1024} for i in items], "empty": "No backups yet."}],
                "note": "Restore with: labdex backup restore FILE (see README). secret.key is never in a backup."}
