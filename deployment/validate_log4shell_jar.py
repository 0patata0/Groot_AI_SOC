#!/usr/bin/env python3
"""Inspect a prepared Spring Boot lab JAR without loading Java or extracting it."""
import hashlib
import io
from pathlib import Path
import stat
import sys
import zipfile

MAX_JAR = 128 * 1024 * 1024


def checked_zip(content):
    archive = zipfile.ZipFile(io.BytesIO(content))
    entries = archive.infolist()
    names = [entry.filename for entry in entries]
    if len(names) != len(set(names)) or len(names) > 20000:
        raise ValueError("duplicate_or_excessive_zip_entries")
    if any(name.startswith("/") or ".." in name.split("/") or "\\" in name for name in names):
        raise ValueError("unsafe_zip_path")
    if any(entry.flag_bits & 1 or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG, stat.S_IFDIR) for entry in entries):
        raise ValueError("unsupported_zip_entry")
    if sum(entry.file_size for entry in entries) > 256 * 1024 * 1024:
        raise ValueError("excessive_expanded_jar")
    return archive


def validate_bytes(content):
    if not 0 < len(content) <= MAX_JAR:
        raise ValueError("jar_size")
    with checked_zip(content) as jar:
        names = set(jar.namelist())
        required = {
            "BOOT-INF/classes/fr/christophetd/log4shell/vulnerableapp/MainController.class",
            "BOOT-INF/classes/fr/christophetd/log4shell/vulnerableapp/VulnerableAppApplication.class",
            "BOOT-INF/classes/fr/christophetd/log4shell/vulnerableapp/LabCsrf.class",
            "BOOT-INF/classes/static/index.html",
            "BOOT-INF/classes/static/app.js",
            "BOOT-INF/classes/static/app.css",
            "org/springframework/boot/loader/JarLauncher.class",
            "BOOT-INF/classes/application.properties",
            "BOOT-INF/classes/log4j2-spring.xml",
        }
        if not required.issubset(names) or any(not jar.read(name) for name in required):
            raise ValueError("new_spring_app_content_missing")
        manifest = jar.read("META-INF/MANIFEST.MF").decode("utf-8").replace("\r\n", "\n").replace("\n ", "")
        fields = {}
        for line in manifest.split("\n\n", 1)[0].splitlines():
            if not line:
                continue
            key, value = line.split(": ", 1)
            if key in fields:
                raise ValueError("duplicate_manifest_field")
            fields[key] = value
        if fields.get("Main-Class") != "org.springframework.boot.loader.JarLauncher" or fields.get("Start-Class") != "fr.christophetd.log4shell.vulnerableapp.VulnerableAppApplication":
            raise ValueError("spring_entrypoint_mismatch")
        for artifact, class_name in (
            ("log4j-api", "org/apache/logging/log4j/LogManager.class"),
            ("log4j-core", "org/apache/logging/log4j/core/lookup/JndiLookup.class"),
        ):
            selected = sorted(name for name in names if name.startswith("BOOT-INF/lib/" + artifact + "-") and name.endswith(".jar"))
            if selected != ["BOOT-INF/lib/" + artifact + "-2.14.1.jar"]:
                raise ValueError("log4j_library_set_mismatch")
            if jar.getinfo(selected[0]).compress_type != zipfile.ZIP_STORED:
                raise ValueError("spring_nested_library_must_be_stored")
            with checked_zip(jar.read(selected[0])) as library:
                props = library.read("META-INF/maven/org.apache.logging.log4j/" + artifact + "/pom.properties").decode("utf-8")
                values = {}
                for line in props.splitlines():
                    line = line.strip()
                    if "=" in line and not line.startswith(("#", "!")):
                        key, value = (part.strip() for part in line.split("=", 1))
                        if key in values:
                            raise ValueError("duplicate_library_property")
                        values[key] = value
                if values.get("groupId") != "org.apache.logging.log4j" or values.get("artifactId") != artifact or values.get("version") != "2.14.1" or not library.read(class_name):
                    raise ValueError("log4j_library_content_mismatch")
    return hashlib.sha256(content).hexdigest()


def validate_path(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= MAX_JAR:
        raise ValueError("invalid_jar_file")
    return validate_bytes(path.read_bytes())


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("jar_path_required")
        print(validate_path(Path(sys.argv[1])))
    except (OSError, ValueError, KeyError, UnicodeError, zipfile.BadZipFile):
        print("prepared_log4shell_jar_contract_failed", file=sys.stderr)
        raise SystemExit(1)
