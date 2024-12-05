import json
import argparse
import os
import html


VERSION = "0.9"
NAME = "Sunshine"

PREFERRED_VULNERABILITY_RATING_METHODS_ORDER = ["CVSSv4",
                                                "CVSSv31"
                                                "CVSSv3"
                                                "CVSSv2"
                                                "OWASP"
                                                "SSVC"
                                                "other"]

VALID_SEVERITIES = {"critical": 4,
                    "high": 3,
                    "medium": 2,
                    "low": 1,
                    "info": 0,
                    "information": 0,
                    "clean": -1}

GREY = '#bcbcbc'
GREEN = '#7dd491'
YELLOW = '#fccd58'
ORANGE = '#ff9335'
RED = '#ff4633'
DARK_RED = '#a10a0a'
LIGHT_BLUE = '#9fc5e8'

BASIC_STYLE = { "color": GREY, "borderWidth": 2 }
INFORMATION_STYLE = { "color": GREEN, "borderWidth": 2 }
LOW_STYLE = { "color": YELLOW, "borderWidth": 2 }
MEDIUM_STYLE = { "color": ORANGE, "borderWidth": 2 }
HIGH_STYLE = { "color": RED, "borderWidth": 2 }
CRITICAL_STYLE = { "color": DARK_RED, "borderWidth": 2 }
TRANSITIVE_VULN_STYLE = { "color": LIGHT_BLUE, "borderWidth": 2 }


STYLES = {"critical": CRITICAL_STYLE,
          "high": HIGH_STYLE,
          "medium": MEDIUM_STYLE,
          "low": LOW_STYLE,
          "information": INFORMATION_STYLE,
          "clean": BASIC_STYLE}


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sunshine - SBOM visualization tool</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.7/css/dataTables.bootstrap5.min.css">
    <script src="https://code.jquery.com/jquery-3.7.1.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/dataTables.bootstrap5.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.2/js/dataTables.buttons.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.8/pdfmake.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.8/vfs_fonts.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.html5.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.print.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>

    <script src="https://fastly.jsdelivr.net/npm/echarts@5.5.1/dist/echarts.min.js"></script>
    <style>
        body {
            margin: 20px;
            height: 100vh;
            background: linear-gradient(to right, #032c57, #1C538E);
        }
        #output {
            white-space: pre-line;
            background-color: #ffffff;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin-top: 10px;
            font-family: "Courier New", "Lucida Console", monospace;
        }
        #chart-container {
            background-color: #ffffff;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            position: relative;
            height: 90vh;
            overflow: hidden;
        }
        #chart-container-placeholder {
            background-color: #fffffF;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }

        #table-container {
            background-color: #fffffF;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        #table-container-placeholder {
            background-color: #fffffF;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }

        #file-input {
            margin: 20px;
        }

        .dataTables_filter {
            display: none;
        }
        th input {
            width: 100%;
            box-sizing: border-box;
        }

        .dataTables_length {
            padding-bottom: 10px !important;
        }
        .light-text {
            color: #baccde;
        }

        .dt-buttons {
            float: right;
        }
        .active>.page-link, .page-link.active {
            background-color: #1C538E !important;
            color: white !important;
        }

        .page-link {
            color: #1C538E;
        }

        #components-table_paginate {
            float: right;
            margin-top: -33px;
        }
    </style>
</head>


<body>
    <h1 class="light-text">Sunshine - SBOM visualization tool</h1>
    <br>
    <span  class="light-text">Analyzed CycloneDX JSON file: <i><FILE_NAME_HERE></i></span>
    <br><br>
    <h3  class="light-text">Components chart</h3>
    <div id="chart-container"></div>
    <br>
    <h3  class="light-text">Components table</h3>
    <div id="table-container"><table id="components-table" class="table table-striped table-bordered" style="width:100%"><TABLE_HERE></table></div>
    <script type="text/javascript">
var dom = document.getElementById('chart-container');
var myChart = echarts.init(dom, null, {
  renderer: 'canvas',
  useDirtyRect: false
});
var app = {};

var option;

const data = <CHART_DATA_HERE>;

option = {
  tooltip: {
        formatter: function(params) {
            return `${params.name}`;
        },
    },
  series: {
    radius: ['15%', '90%'],
    type: 'sunburst',
    sort: undefined,
    emphasis: {
      focus: 'ancestor'
    },
    data: data,
    label: {
      rotate: 'radial',
      show: false
    },
    levels: []
  }
};

if (option && typeof option === 'object') {
  myChart.setOption(option);
}

window.addEventListener('resize', myChart.resize);

let table = $('#components-table').DataTable({
    "order": [[ 1, "asc" ]],
    pageLength: 10,
    dom: 'Blfrtip',
    lengthMenu: [
        [10, 25, 50, -1],
        [10, 25, 50, 'All']
    ],
    buttons: [
      { extend: 'copy', className: 'btn btn-dark mb-3 btn-sm' },
      { extend: 'csv', className: 'btn btn-secondary mb-3 btn-sm' },
      { extend: 'excel', className: 'btn btn-success mb-3 btn-sm' },
      { extend: 'pdf', className: 'btn btn-danger mb-3 btn-sm' },
      { extend: 'print', className: 'btn btn-info mb-3 btn-sm' }
    ],
    orderCellsTop: true,
    "autoWidth": true
  });

$('#components-table thead input').on('keyup change', function () {
    let columnIndex = $(this).parent().index();
    table.column(columnIndex).search(this.value).draw();
});
      </script>
      <br><br>
    </body>
</html>
"""


def custom_print(text):
    if __name__ == "__web__":
        from js import writeToLog
        writeToLog(text)
    else:
        print(text)


class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return super().default(obj)


def create_fake_component(bom_ref):
    return {"name": bom_ref,
            "version": "-",
            "type": "-",
            "depends_on": set(),
            "dependency_of": set(),
            "vulnerabilities": [],
            "max_vulnerability_severity": "clean",
            "has_transitive_vulnerabilities": False,
            "visited": False}


def get_severity_by_score(score):
    score = float(score)
    if score >= 9:
        return "critical"
    elif score >= 7:
        return "high"
    elif score >= 4:
        return "medium"
    elif score > 0:
        return "low"
    else:
        return "information"


def parse_vulnerability_data(vulnerability):
    vuln_id = vulnerability["id"]

    vuln_severity = None
    for rating in vulnerability["ratings"]:
        for preferred_rating_method in PREFERRED_VULNERABILITY_RATING_METHODS_ORDER:
            if rating["method"] == preferred_rating_method:
                if "severity" in rating:
                    rating_vuln_severity = rating["severity"]
                    if rating_vuln_severity.lower() in VALID_SEVERITIES:
                        if rating_vuln_severity.lower() == "info":
                            rating_vuln_severity = "information"
                        vuln_severity = rating_vuln_severity.lower()
                        break
                if "score" in rating:
                    vuln_severity = get_severity_by_score(rating["score"])
                    break

    if vuln_severity is None:
        if "ratings" not in vulnerability:
            vuln_severity = get_severity_by_score(0)
        elif len(vulnerability["ratings"]) == 0:
            vuln_severity = get_severity_by_score(0)
        else:
            for rating in vulnerability["ratings"]:
                if "severity" in rating:
                    rating_vuln_severity = rating["severity"]
                    if rating_vuln_severity.lower() in VALID_SEVERITIES:
                        vuln_severity = rating_vuln_severity.lower()
                        break
                if "score" in rating:
                    vuln_severity = get_severity_by_score(rating["score"])
                    break

    if vuln_severity is None:
        vuln_severity = get_severity_by_score(0)

    return vuln_id, vuln_severity


def get_bom_ref(component_json, all_bom_refs):
    if "bom-ref" in component_json:
        bom_ref = component_json["bom-ref"]
    else:
        custom_print(f"WARNING: component with name '{component_json['name']}' and version '{component_json["version"]}' does not have a 'bom-ref'. I'll search for a match...")
        for potential_bom_ref in all_bom_refs:
            guessed_name_01 = f'{component_json["name"]}@{component_json["version"]}'
            guessed_name_02 = f'{component_json["name"]}::{component_json["version"]}'
            guessed_name_03 = f'{component_json["name"]}:{component_json["version"]}'

            for test in [guessed_name_01, guessed_name_02, guessed_name_03]:
                if potential_bom_ref.endswith(f"/{test}"):
                    custom_print(f"Match found: {potential_bom_ref}")
                    return potential_bom_ref
                if potential_bom_ref.endswith(f"/{test}:"):
                    custom_print(f"Match found: {potential_bom_ref}")
                    return potential_bom_ref
                if potential_bom_ref.endswith(f":{test}"):
                    custom_print(f"Match found: {potential_bom_ref}")
                    return potential_bom_ref
                if potential_bom_ref.endswith(f":{test}:"):
                    custom_print(f"Match found: {potential_bom_ref}")
                    return potential_bom_ref

        custom_print(f"Match not found. I'll create a fake one.")
        bom_ref = f"{hash(json.dumps(component_json, sort_keys=True, cls=SetEncoder))}"
    return bom_ref


def create_or_update_bom_ref_entry(bom_refs, component):
    if component["bom-ref"] not in bom_refs:
        bom_refs[component["bom-ref"]] = {"name": component["name"] if "name" in component else "-", 
                                          "version": component["version"] if "version" in component else "-"}
    else:
        if bom_refs[component["bom-ref"]]["name"] == "-" and "name" in component:
            bom_refs[component["bom-ref"]]["name"] = component["name"]
        if bom_refs[component["bom-ref"]]["version"] == "-" and "version" in component:
            bom_refs[component["bom-ref"]]["version"] = component["version"]


def normalize_bom_ref(bom_refs, bom_ref, only_valid_components=True):
    for component_bom_ref, component_data in bom_refs.items():
        if only_valid_components is False:
            if bom_ref == component_bom_ref:
                return bom_ref
        else:
            if bom_ref == component_bom_ref and component_data["name"] != "-" and component_data["version"] != "-":
                return bom_ref

    for component_bom_ref, component_data in bom_refs.items():
        # look with version
        guessed_name_01 = f'{component_data["name"]}@{component_data["version"]}'
        guessed_name_02 = f'{component_data["name"]}::{component_data["version"]}'
        guessed_name_03 = f'{component_data["name"]}:{component_data["version"]}'

        for test in [guessed_name_01, guessed_name_02, guessed_name_03]:
            if bom_ref.endswith(f"/{test}"):
                return bom_ref
            if bom_ref.endswith(f"/{test}:"):
               return bom_ref
            if bom_ref.endswith(f":{test}"):
                return bom_ref
            if bom_ref.endswith(f":{test}:"):
                return bom_ref

    number_of_results = 0
    result = None
    for component_bom_ref, component_data in bom_refs.items():
        # look without version        
        if f'/{component_data["name"]}@' in bom_ref:
            number_of_results += 1
            result = component_bom_ref
        elif f'/{component_data["name"]}:' in bom_ref:
            number_of_results += 1
            result = component_bom_ref
        elif f':{component_data["name"]}:' in bom_ref:
            number_of_results += 1
            result = component_bom_ref
        elif f':{component_data["name"]}@' in bom_ref:
            number_of_results += 1
            result = component_bom_ref
    if number_of_results == 1:  # I want just one result, otherwise it means the sbom is ambiguous and I can't make any educated guess
        return result

    return None

def has_bom_ref_components(bom_refs, bom_ref, only_valid_components=False):
    return normalize_bom_ref(bom_refs, bom_ref) is not None


def get_all_bom_refs(data):
    bom_refs = {}
    meta_bom_ref_is_used = False

    root_keywords = []
    if "components" in data:
        root_keywords.append("components")
    if "services" in data:
        root_keywords.append("services")

    for root_keyword in root_keywords:
        for component in data[root_keyword]:
            if "bom-ref" in component:
                create_or_update_bom_ref_entry(bom_refs, component)

            if root_keyword == "services":
                component_with_services = component
                while "services" in component_with_services:
                    for sub_component in component_with_services["services"]:
                        if "bom-ref" in sub_component:
                            create_or_update_bom_ref_entry(bom_refs, sub_component)
                        component_with_services = sub_component

    for root_keyword in root_keywords:
        for component in data[root_keyword]:
            if "dependencies" in component:
                for dependency in component["dependencies"]:
                    if "ref" in dependency:
                        create_or_update_bom_ref_entry(bom_refs, {"bom-ref":  dependency["ref"]})

    if "dependencies" in data:
        for dependency in data["dependencies"]:
            if "ref" in dependency:
                create_or_update_bom_ref_entry(bom_refs, {"bom-ref":  dependency["ref"]})

            if "dependsOn" in dependency:
                for depends_on in dependency["dependsOn"]:
                    create_or_update_bom_ref_entry(bom_refs, {"bom-ref":  depends_on})

    if "metadata" in data:
        if "component" in data["metadata"]:
            if "bom-ref" in data["metadata"]["component"]:
                if has_bom_ref_components(bom_refs, data["metadata"]["component"]["bom-ref"]):
                    meta_bom_ref_is_used = True
                    create_or_update_bom_ref_entry(bom_refs, data["metadata"]["component"])

    return bom_refs, meta_bom_ref_is_used


def parse_json_data(data):
    all_bom_refs, meta_bom_ref_is_used = get_all_bom_refs(data)

    components = {}

    root_keywords = []
    if "components" in data:
        root_keywords.append("components")
    if "services" in data:
        root_keywords.append("services")

    if "metadata" in data:
        if "component" in data["metadata"]:
            component = data["metadata"]["component"]
            if meta_bom_ref_is_used is True:
                new_component = {"name": component["name"],
                                 "version": component["version"] if "version" in component else "-",
                                 "type": component["type"] if "type" in component else "-",
                                 "depends_on": set(),
                                 "dependency_of": set(),
                                 "vulnerabilities": [],
                                 "max_vulnerability_severity": "clean",
                                 "has_transitive_vulnerabilities": False,
                                 "visited": False}

                bom_ref = get_bom_ref(component, all_bom_refs)
                components[bom_ref] = new_component

    for root_keyword in root_keywords:
        for component in data[root_keyword]:
            new_component = {"name": component["name"],
                             "version": component["version"] if "version" in component else "-",
                             "type": component["type"] if "type" in component else "-",
                             "depends_on": set(),
                             "dependency_of": set(),
                             "vulnerabilities": [],
                             "max_vulnerability_severity": "clean",
                             "has_transitive_vulnerabilities": False,
                             "visited": False}

            bom_ref = get_bom_ref(component, all_bom_refs)
            components[bom_ref] = new_component

        if root_keyword == "services":
            if "services" in component:
                for sub_component in component["services"]:
                    new_component = {"name": sub_component["name"],
                                     "version": sub_component["version"] if "version" in sub_component else "-",
                                     "type": sub_component["type"] if "type" in sub_component else "-",
                                     "depends_on": set(),
                                     "dependency_of": set(),
                                     "vulnerabilities": [],
                                     "max_vulnerability_severity": "clean",
                                     "has_transitive_vulnerabilities": False,
                                     "visited": False}

                    bom_ref = get_bom_ref(sub_component, all_bom_refs)
                    components[bom_ref] = new_component

        # sometimes dependencies are declared inside a component, I'll check that now
        for component in data[root_keyword]:
            bom_ref = get_bom_ref(component, all_bom_refs)

            if "dependencies" in component:
                for dependency in component["dependencies"]:
                    depends_on = dependency["ref"]
                    if depends_on not in components:
                        custom_print(f"WARNING: 'ref' '{depends_on}' is used in 'dependencies' inside a component but it's not declared in 'components'. I'll search for a match...")
                        guessed_bom_ref = normalize_bom_ref(all_bom_refs, depends_on)
                        if guessed_bom_ref is None:
                            custom_print(f"Match not found. I'll create a fake one.")
                            components[depends_on] = create_fake_component(depends_on)
                        else:
                            custom_print(f"Match found: {guessed_bom_ref}")
                            depends_on = guessed_bom_ref

                    components[bom_ref]["depends_on"].add(depends_on)
                    components[depends_on]["dependency_of"].add(bom_ref)

        # sometimes vulnerabilities are declared inside a component, I'll check that now
        for component in data[root_keyword]:
            bom_ref = get_bom_ref(component, all_bom_refs)

            if "vulnerabilities" in component:
                for vulnerability in component["vulnerabilities"]:
                    vuln_id, vuln_severity = parse_vulnerability_data(vulnerability)

                    vulnerability_data = {"id": vuln_id, "severity": vuln_severity}
                    if vulnerability_data not in components[bom_ref]["vulnerabilities"]:
                        components[bom_ref]["vulnerabilities"].append(vulnerability_data)
                    if VALID_SEVERITIES[vuln_severity] > VALID_SEVERITIES[components[bom_ref]["max_vulnerability_severity"]]:
                        components[bom_ref]["max_vulnerability_severity"] = vuln_severity

    if "dependencies" in data:
        for dependency in data["dependencies"]:
            bom_ref = dependency["ref"]
            if bom_ref not in components:
                custom_print(f"WARNING: 'ref' '{bom_ref}' is used in 'dependencies' but it's not declared in 'components'. I'll search for a match...")
                guessed_bom_ref = normalize_bom_ref(all_bom_refs, bom_ref)
                if guessed_bom_ref is None:
                    custom_print(f"Match not found. I'll create a fake one.")
                    components[bom_ref] = create_fake_component(bom_ref)
                else:
                    custom_print(f"Match found: {guessed_bom_ref}")
                    bom_ref = guessed_bom_ref

            if "dependsOn" in dependency:
                for depends_on in dependency["dependsOn"]:
                    if depends_on not in components:
                        custom_print(f"WARNING: 'dependsOn' '{depends_on}' is used in 'dependencies' but it's not declared in 'components'. I'll search for a match...")
                        guessed_bom_ref = normalize_bom_ref(all_bom_refs, depends_on)
                        if guessed_bom_ref is None:
                            custom_print(f"Match not found. I'll create a fake one.")
                            components[depends_on] = create_fake_component(depends_on)
                        else:
                            custom_print(f"Match found: {guessed_bom_ref}")
                            depends_on = guessed_bom_ref

                    components[bom_ref]["depends_on"].add(depends_on)
                    components[depends_on]["dependency_of"].add(bom_ref)

    if "vulnerabilities" in data:
        for vulnerability in data["vulnerabilities"]:
            vuln_id, vuln_severity = parse_vulnerability_data(vulnerability)

            for affects in vulnerability["affects"]:
                bom_ref = affects["ref"]
                if bom_ref not in components:
                    custom_print(f"WARNING: 'ref' '{bom_ref}' is used in 'vulnerabilities' but it's not declared in 'components'. I'll create a fake one.")
                    components[bom_ref] = create_fake_component(bom_ref)

                vulnerability_data = {"id": vuln_id, "severity": vuln_severity}
                if vulnerability_data not in components[bom_ref]["vulnerabilities"]:
                    components[bom_ref]["vulnerabilities"].append(vulnerability_data)
                if VALID_SEVERITIES[vuln_severity] > VALID_SEVERITIES[components[bom_ref]["max_vulnerability_severity"]]:
                    components[bom_ref]["max_vulnerability_severity"] = vuln_severity

    return components


def parse_string(input_string):
    custom_print("Parsing input string...")
    data = json.loads(input_string)
    return parse_json_data(data)


def parse_file(input_file_path):
    custom_print("Parsing input file...")
    with open(input_file_path, 'r') as file:
        data = json.load(file)
    return parse_json_data(data)


def prepare_chart_element_name(component):
    if component["version"] != "-":
        name = f'{html.escape(component["name"])} <b>{html.escape(component["version"])}</b>'
    else:
        name = f'{html.escape(component["name"])}'

    if len(component["vulnerabilities"]) > 0:
        name += "<br>"
        vulns = {}
        for vulnerability in component["vulnerabilities"]:
            vulns[f'<li>{html.escape(vulnerability["id"])} ({html.escape(vulnerability["severity"].title())})</li>'] = VALID_SEVERITIES[vulnerability["severity"]]

        vulns = dict(sorted(vulns.items(), key=lambda item: item[1], reverse=True))

        vulns_to_be_shown = list(vulns.keys())
        if len(vulns_to_be_shown) > 10:
            vulns_to_be_shown = vulns_to_be_shown[:10]
            vulns_to_be_shown.append("<li>...</li>")


        name += "".join(vulns_to_be_shown)
    return name


def determine_style(component):
    if component["max_vulnerability_severity"] != "clean":
        return STYLES[component["max_vulnerability_severity"]]
    if component["has_transitive_vulnerabilities"] is True:
        return TRANSITIVE_VULN_STYLE
    else:
        return STYLES[component["max_vulnerability_severity"]]


def get_children(components, component, parents):
    children = []
    value = 0
    has_vulnerable_children_or_is_vulnerable = False
    if len(component["vulnerabilities"]) > 0:
        has_vulnerable_children_or_is_vulnerable = True
        component["has_transitive_vulnerabilities"] = True
    for depends_on in component["depends_on"]:
        child_name = prepare_chart_element_name(components[depends_on])
        child_component = components[depends_on]
        child_component["visited"] = True
        if depends_on not in parents:  # this is done to avoid infinite recursion in case of circular dependencies
            parents.append(depends_on)
            child_children, children_value, has_vulnerable_children_or_is_vulnerable = get_children(components, child_component, parents)
            if len(child_component["vulnerabilities"]) > 0 or child_component["has_transitive_vulnerabilities"] is True or has_vulnerable_children_or_is_vulnerable is True:
                component["has_transitive_vulnerabilities"] = True
                has_vulnerable_children_or_is_vulnerable = True

            value += children_value
            
            children.append({"name": child_name,
                             "children": child_children,
                             "value": children_value,
                             "itemStyle": determine_style(child_component)
                             })
        else:
            value += 1
            for child_depends_on in child_component["depends_on"]:
                if len(child_depends_on["vulnerabilities"]) > 0 or child_depends_on["has_transitive_vulnerabilities"] is True:
                    child_component["has_transitive_vulnerabilities"] = True
                    break

            children.append({"name": child_name,
                             "children": [],
                             "value": 1,
                             "itemStyle": determine_style(child_component)
                             })

    if value == 0:
        value = 1

    return children, value, has_vulnerable_children_or_is_vulnerable


def add_root_component(components, component, data, bom_ref):
    component["visited"] = True
    parents = [bom_ref]
    root_name = prepare_chart_element_name(component)
    root_children, root_value, has_vulnerable_children_or_is_vulnerable = get_children(components, component, parents)

    if has_vulnerable_children_or_is_vulnerable is True:
        component["has_transitive_vulnerabilities"] = True

    new_element = {"name": root_name,
                   "children": root_children,
                   "value": root_value,
                   "itemStyle": determine_style(component)
                   }
    data.append(new_element)


def build_echarts_data(components):
    data = []

    for bom_ref, component in components.items():
        if len(component["dependency_of"]) != 0:
            continue

        add_root_component(components, component, data, bom_ref)

    return data


def double_check_if_all_components_were_taken_into_account(components, echart_data):
    # this should happen only for circular dependencies
    for bom_ref, component in components.items():
        if component["visited"] is False:
            add_root_component(components, component, echart_data, bom_ref)


def component_badge_for_table(component):
    component_on_display = ""
    component_on_display += '<span class="badge text-bg-secondary">' + html.escape(component["name"])
    if component["version"] != "-":
        component_on_display += " " + html.escape(component["version"])
    return component_on_display + "</span>"


def vulnerability_badge_for_table(component):
    vulns = {}
    for vulnerability in component["vulnerabilities"]:
        if vulnerability["severity"] == "critical":
            badge_class = 'bg-dark-red'
        elif vulnerability["severity"] == "high":
            badge_class = 'bg-danger'
        elif vulnerability["severity"] == "medium":
            badge_class = 'bg-orange'
        elif vulnerability["severity"] == "low":
            badge_class = 'bg-yellow'
        elif vulnerability["severity"] in ["information", "info"]:
            badge_class = 'bg-success'

        vulns[f'<span class="badge {badge_class}">{html.escape(vulnerability["severity"].title())} &#x2192; {html.escape(vulnerability["id"])}</span>'] = VALID_SEVERITIES[vulnerability["severity"]]
    vulns = dict(sorted(vulns.items(), key=lambda item: item[1], reverse=True))
    vulns_to_be_shown = list(vulns.keys())
    return vulns_to_be_shown


def build_table_content(components):
    rows = ["""<thead>
        <tr>
            <th>Component</th>
            <th>Depends on</th>
            <th>Dependency of</th>
            <th>Direct vulnerabilities</th>
            <th>Transitive vulnerabilities</th>
            <th>License</th>
        </tr>
        <tr>
            <th><input type="text" placeholder="Search Component" class="form-control"></th>
            <th><input type="text" placeholder="Search Depends on" class="form-control"></th>
            <th><input type="text" placeholder="Search Dependency of" class="form-control"></th>
            <th><input type="text" placeholder="Search Direct vulnerabilities" class="form-control"></th>
            <th><input type="text" placeholder="Search Transitive vulnerabilities" class="form-control"></th>
            <th><input type="text" placeholder="Search License" class="form-control"></th>
        </tr>
    </thead>"""]
    rows.append("<tbody>")
    for bom_ref, component in components.items():
        new_row = "<tr>"

        new_row += "<td>" + component_badge_for_table(component) + "</td>"


        if len(component["depends_on"]) == 0:
            new_row += "<td>-</td>"
        else:
            new_row += "<td>"
            depends_on_components_list = []
            for depends_on in component["depends_on"]:
                component_depends_on = components[depends_on]
                component_depends_on_display = component_badge_for_table(component_depends_on)
                depends_on_components_list.append(component_depends_on_display)

            new_row += '<span style="display: none;">, </span><br>'.join(depends_on_components_list)
            new_row += "</td>"

        if len(component["dependency_of"]) == 0:
            new_row += "<td>-</td>"
        else:
            new_row += "<td>"
            dependency_of_components_list = []
            for dependency_of in component["dependency_of"]:
                component_dependency_of = components[dependency_of]
                component_dependency_of_display = component_badge_for_table(component_dependency_of)
                dependency_of_components_list.append(component_dependency_of_display)
            new_row += '<span style="display: none;">, </span><br>'.join(dependency_of_components_list)
            new_row += "</td>"

        if len(component["vulnerabilities"]) == 0:
            new_row += "<td>-</td>"
        else:
            vulns_to_be_shown = vulnerability_badge_for_table(component)
            new_row += "<td>" + '<span style="display: none;">, </span><br>'.join(vulns_to_be_shown) + "</td>"

        new_row += "<td>TODO TRANSITIVE VULNS</td>"

        new_row += "<td>TODO LICENSES</td>"

        new_row += "</tr>\n"

        rows.append(new_row)

    rows.append("</tbody>")

    return "".join(rows)


def write_output_file(html_content, output_file_path):
    with open(output_file_path, "w") as text_file:
        text_file.write(html_content)


def main_cli(input_file_path, output_file_path):
    if not os.path.exists(input_file_path):
        custom_print(f"File does not exist: '{input_file_path}'")
        exit()

    components = parse_file(input_file_path)
    """try:
        components = parse_file(input_file_path)
    except Exception as e:
        custom_print(f"Error parsing input file: {e}")
        exit()"""

    echart_data = build_echarts_data(components)
    double_check_if_all_components_were_taken_into_account(components, echart_data)

    table_content = build_table_content(components)
    
    html_content = HTML_TEMPLATE.replace("<CHART_DATA_HERE>", json.dumps(echart_data, indent=2))
    html_content = html_content.replace("<FILE_NAME_HERE>", os.path.basename(input_file_path))
    html_content = html_content.replace("<TABLE_HERE>", table_content)
    
    write_output_file(html_content, output_file_path)
    custom_print("Done.")


def main_web(input_string):
    try:
        components = parse_string(input_string)
    except Exception as e:
        custom_print(f"Error parsing input string: {e}")
        exit()

    echart_data = build_echarts_data(components)
    double_check_if_all_components_were_taken_into_account(components, echart_data)

    echart_data = json.dumps(echart_data, indent=2)
    table_content = build_table_content(components)
    
    return echart_data, table_content


if __name__ == "__main__":
    custom_print(f'''
 ▗▄▄▖▗▖ ▗▖▗▖  ▗▖ ▗▄▄▖▗▖ ▗▖▗▄▄▄▖▗▖  ▗▖▗▄▄▄▖
▐▌   ▐▌ ▐▌▐▛▚▖▐▌▐▌   ▐▌ ▐▌  █  ▐▛▚▖▐▌▐▌   
 ▝▀▚▖▐▌ ▐▌▐▌ ▝▜▌ ▝▀▚▖▐▛▀▜▌  █  ▐▌ ▝▜▌▐▛▀▀▘
▗▄▄▞▘▝▚▄▞▘▐▌  ▐▌▗▄▄▞▘▐▌ ▐▌▗▄█▄▖▐▌  ▐▌▐▙▄▄▖ v{VERSION}
    ''')

    parser = argparse.ArgumentParser(description=f"{NAME}: actionable CycloneDX visualization")
    parser.add_argument("-v", "--version", help="show program version", action="store_true")
    parser.add_argument("-i", "--input", help="path of input CycloneDX file")
    parser.add_argument("-o", "--output", help="path of output HTML file")
    args = parser.parse_args()

    if args.version:
        exit()

    if not args.input or not args.output:
        parser.print_help()
        exit()

    input_file_path = args.input
    output_file_path = args.output
    main_cli(input_file_path, output_file_path)


if __name__ == "__web__":
    echart_data, table_content = main_web(INPUT_DATA)
    OUTPUT_CHART_DATA = echart_data
    OUTPUT_TABLE_DATA = table_content

