#!/usr/bin/env python3
"""Docker Hub 이미지를 데몬 없이 내려받아 `docker load` 가능한 OCI 레이아웃 tar 로 저장 (오프라인 반입용).
사용: python3 pull_image.py <repo> <tag> [--arch amd64] [--out FILE]
  예) python3 pull_image.py nousresearch/hermes-agent v2026.9.24 --out hermes-agent_v2026.9.24_amd64.tar
- 레지스트리 v2 API(토큰 인증) → 인덱스/매니페스트 → config + layer blob 을 sha256 검증하며 저장.
- 표준 라이브러리만 사용. TLS 검증은 certifi 가 있으면 사용, 없으면 무검증 폴백(blob 은 다이제스트로 무결성 보장).
- 결과: oci-layout + index.json(ref.name=<repo>:<tag>) + blobs/sha256/* 를 담은 tar. B 에서 `docker load -i FILE`.
"""
import argparse, hashlib, io, json, os, ssl, sys, tarfile, tempfile, time, urllib.request

REG = "https://registry-1.docker.io"
AUTH = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])

def ctx():
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        try:
            c = ssl.create_default_context(); c.load_default_certs(); return c
        except Exception:
            pass
    return ssl._create_unverified_context()

CTX = ctx()

def get(url, headers=None, stream=False):
    req = urllib.request.Request(url, headers=headers or {})
    for attempt in range(4):
        try:
            return urllib.request.urlopen(req, timeout=60, context=CTX)
        except Exception as e:
            if attempt == 3: raise
            time.sleep(2 * (attempt + 1))

def token(repo):
    with get(AUTH.format(repo=repo)) as r:
        return json.load(r)["token"]

def manifest(repo, ref, tok):
    with get(f"{REG}/v2/{repo}/manifests/{ref}", {"Authorization": f"Bearer {tok}", "Accept": ACCEPT}) as r:
        raw = r.read(); ct = r.headers.get("Content-Type", "")
    return json.loads(raw), raw, ct

def blob_to_file(repo, digest, tok, path, size=None):
    algo, hexd = digest.split(":")
    h = hashlib.new(algo); done = 0; t0 = time.time()
    with get(f"{REG}/v2/{repo}/blobs/{digest}", {"Authorization": f"Bearer {tok}"}) as r, open(path, "wb") as f:
        while True:
            chunk = r.read(1 << 20)
            if not chunk: break
            f.write(chunk); h.update(chunk); done += len(chunk)
            if size and done % (50 << 20) < (1 << 20):
                print(f"    {done/1e6:8.1f}/{size/1e6:.1f} MB", flush=True)
    if h.hexdigest() != hexd:
        raise SystemExit(f"DIGEST MISMATCH {digest}")
    return done

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("repo"); ap.add_argument("tag")
    ap.add_argument("--arch", default="amd64"); ap.add_argument("--os", default="linux"); ap.add_argument("--out")
    a = ap.parse_args()
    repo = a.repo if "/" in a.repo else f"library/{a.repo}"
    out = a.out or f"{a.repo.replace('/', '_')}_{a.tag}_{a.arch}.tar"
    tok = token(repo)
    m, raw, ct = manifest(repo, a.tag, tok)
    if "manifests" in m:  # index / manifest list → pick platform
        cands = [x for x in m["manifests"] if x.get("platform", {}).get("architecture") == a.arch and x.get("platform", {}).get("os") == a.os]
        if not cands: raise SystemExit(f"no {a.os}/{a.arch} manifest in index")
        mdig = cands[0]["digest"]; print(f"index → {a.os}/{a.arch} manifest {mdig[:19]}")
        m, raw, ct = manifest(repo, mdig, tok)
    mdigest = "sha256:" + hashlib.sha256(raw).hexdigest()
    cfg = m["config"]; layers = m["layers"]
    total = cfg["size"] + sum(l["size"] for l in layers)
    print(f"manifest {mdigest[:19]} type={ct}\nconfig {cfg['digest'][:19]} ({cfg['size']} B), {len(layers)} layers, total {total/1e6:.0f} MB")
    tmp = tempfile.mkdtemp(prefix="pull_")
    blobs = os.path.join(tmp, "blobs", "sha256"); os.makedirs(blobs)
    with open(os.path.join(blobs, mdigest.split(':')[1]), "wb") as f: f.write(raw)
    blob_to_file(repo, cfg["digest"], tok, os.path.join(blobs, cfg["digest"].split(':')[1]))
    for i, l in enumerate(layers, 1):
        print(f"  layer {i}/{len(layers)} {l['digest'][:19]} {l['size']/1e6:.1f} MB", flush=True)
        blob_to_file(repo, l["digest"], tok, os.path.join(blobs, l["digest"].split(':')[1]), l["size"])
    index = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
             "manifests": [{"mediaType": ct or "application/vnd.oci.image.manifest.v1+json", "digest": mdigest, "size": len(raw),
                            "annotations": {"org.opencontainers.image.ref.name": f"{a.repo}:{a.tag}", "io.containerd.image.name": f"docker.io/{repo}:{a.tag}"}}]}
    with open(os.path.join(tmp, "index.json"), "w") as f: json.dump(index, f)
    with open(os.path.join(tmp, "oci-layout"), "w") as f: json.dump({"imageLayoutVersion": "1.0.0"}, f)
    print("packing tar …", flush=True)
    with tarfile.open(out, "w") as t:
        for name in ("oci-layout", "index.json"): t.add(os.path.join(tmp, name), arcname=name)
        t.add(os.path.join(tmp, "blobs"), arcname="blobs")
    for root, _, files in os.walk(tmp):
        for fn in files: os.remove(os.path.join(root, fn))
    for root, dirs, _ in os.walk(tmp, topdown=False):
        for d in dirs: os.rmdir(os.path.join(root, d))
    os.rmdir(tmp)
    print(f"DONE {out} ({os.path.getsize(out)/1e6:.0f} MB)  image-id(config)={cfg['digest']}")

if __name__ == "__main__":
    main()
