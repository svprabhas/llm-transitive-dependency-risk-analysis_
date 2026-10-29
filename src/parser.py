import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

# Matches one line of `mvn dependency:tree` text output, e.g.
#   +- org.springframework.boot:spring-boot-starter-web:jar:2.0.0:compile
#   |  \- com.fasterxml.jackson.core:jackson-databind:jar:2.9.5:compile
# Each nesting level adds 3 characters of indentation ("|  " or "   ").
TREE_LINE = re.compile(r'^((?:\|  |   )*)(\+-|\\-) (\S+)')


class DependencyParser:
    """
    Stage 1 and 2: resolve the dependency graph.

    Preferred route: run `mvn dependency:tree` and read the real tree, so depth
    and path come from Maven itself.
    Fallback route: read the direct <dependency> entries of pom.xml. This gives
    direct dependencies only (depth 1). Nothing is guessed: if a version cannot
    be read from the pom, it is left as None and the node is marked unresolved.

    After resolve_transitive_graph() runs, `self.mode` is "maven" or "fallback"
    and `self.maven_error` holds the reason when Maven was not used. Record
    both in the report so a fallback run is never mistaken for a full run.
    """

    def __init__(self, pom_path, timeout=600):
        self.pom_path = pom_path
        self.timeout = timeout
        self.mode = None
        self.maven_error = None

    # ------------------------------------------------------------------ #
    def resolve_transitive_graph(self):
        nodes = self._try_maven()
        if nodes:
            self.mode = "maven"
            print(f"[+] Successfully extracted full transitive tree via Maven ({len(nodes)} nodes).")
            return nodes

        self.mode = "fallback"
        print(f"[-] Maven route not used: {self.maven_error}")
        print("[-] Falling back to direct-dependency parsing of pom.xml (depth 1 only).")
        return self._parse_pom_direct()

    # ------------------------------------------------------------------ #
    def _find_maven(self):
        project_dir = os.path.dirname(os.path.abspath(self.pom_path))
        wrapper = "mvnw.cmd" if os.name == "nt" else "mvnw"
        wrapper_path = os.path.join(project_dir, wrapper)
        if os.path.exists(wrapper_path):
            return wrapper_path
        return shutil.which("mvn") or shutil.which("mvn.cmd")

    def _try_maven(self):
        mvn = self._find_maven()
        if not mvn:
            self.maven_error = "Maven executable not found on PATH"
            return []
        cmd = [mvn, "-B", "dependency:tree", "-DoutputType=text",
               "-f", self.pom_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=self.timeout)
        except subprocess.TimeoutExpired:
            self.maven_error = f"Maven timed out after {self.timeout}s"
            return []
        except Exception as e:
            self.maven_error = f"Maven could not be started: {e}"
            return []

        if result.returncode != 0:
            tail = " | ".join(result.stdout.strip().splitlines()[-5:])
            self.maven_error = f"Maven exited with code {result.returncode}: {tail}"
            return []

        nodes = self._parse_maven_tree(result.stdout)
        if not nodes:
            self.maven_error = "Maven ran but no dependency lines were parsed"
        return nodes

    # ------------------------------------------------------------------ #
    @staticmethod
    def _split_coordinate(token):
        """groupId:artifactId:type[:classifier]:version:scope"""
        parts = token.split(":")
        if len(parts) == 5:
            g, a, _type, v, scope = parts
        elif len(parts) == 6:
            g, a, _type, _classifier, v, scope = parts
        else:
            return None
        return g, a, v, scope

    def _parse_maven_tree(self, text):
        nodes = []
        seen = set()
        stack = []          # stack[i] = coordinate at depth i + 1
        expecting_root = False

        for raw in text.splitlines():
            line = re.sub(r'^\[\w+\]\s?', '', raw.rstrip())

            if line.startswith("---") and "tree" in line:
                expecting_root = True      # a new module's tree starts here
                stack = []
                continue

            match = TREE_LINE.match(line)
            if match:
                depth = len(match.group(1)) // 3 + 1
                coord = self._split_coordinate(match.group(3))
                if not coord:
                    continue
                g, a, v, scope = coord
                stack = stack[:depth - 1]
                stack.append(f"{g}:{a}:{v}")

                key = (g, a, v)
                if key in seen:            # keep the first path found
                    continue
                seen.add(key)
                nodes.append({
                    "ecosystem": "Maven",
                    "name": f"{g}:{a}",
                    "version": v,
                    "scope": scope,
                    "depth": depth,
                    "path": ["root-application"] + list(stack),
                    "resolved": True,
                })
            elif expecting_root and line.count(":") >= 3 and " " not in line.strip():
                expecting_root = False     # the module's own coordinate line

        return nodes

    # ------------------------------------------------------------------ #
    @staticmethod
    def _strip_ns(root):
        for elem in root.iter():
            if isinstance(elem.tag, str) and "}" in elem.tag:
                elem.tag = elem.tag.split("}", 1)[1]

    def _parse_pom_direct(self):
        nodes = []
        try:
            root = ET.parse(self.pom_path).getroot()
        except Exception as e:
            print(f"[-] Could not read {self.pom_path}: {e}")
            return nodes
        self._strip_ns(root)

        props = {}
        props_elem = root.find("properties")
        if props_elem is not None:
            for p in props_elem:
                if p.text:
                    props[p.tag] = p.text.strip()

        deps_elem = root.find("dependencies")     # direct dependencies only
        if deps_elem is None:
            return nodes

        for dep in deps_elem.findall("dependency"):
            g = dep.findtext("groupId", default="").strip()
            a = dep.findtext("artifactId", default="").strip()
            v = dep.findtext("version", default="").strip()
            scope = dep.findtext("scope", default="compile").strip()
            if not g or not a:
                continue

            if v.startswith("${") and v.endswith("}"):
                v = props.get(v[2:-1], "")        # property lookup, else unresolved
            version = v if v and not v.startswith("${") else None

            nodes.append({
                "ecosystem": "Maven",
                "name": f"{g}:{a}",
                "version": version,
                "scope": scope,
                "depth": 1,
                "path": ["root-application", f"{g}:{a}:{version or 'UNRESOLVED'}"],
                "resolved": version is not None,
            })
        return nodes