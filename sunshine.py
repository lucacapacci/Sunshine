import json
import argparse
import os

VERSION = "0.9"
NAME = "Sunshine"

PREFERRED_VULNERABILITY_RATING_METHODS_ORDER = ["CVSSv4",
                                                "CVSSv31"
                                                "CVSSv3"
                                                "CVSSv2"
                                                "OWASP"
                                                "SSVC"
                                                "other"]

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
    <head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">  
      <title>SBOM</title>
      <style>
* {
  margin: 0;
  padding: 0;
}
#chart-container {
  position: relative;
  height: 100vh;
  overflow: hidden;
}
      </style>
    </head>
    <body>
      <div id="chart-container"></div>
      <script src="https://fastly.jsdelivr.net/npm/echarts@5.5.1/dist/echarts.min.js"></script>
      <script type="text/javascript">
var dom = document.getElementById('chart-container');
var myChart = echarts.init(dom, null, {
  renderer: 'canvas',
  useDirtyRect: false
});
var app = {};

var option;

const item1 = {
  color: '#F54F4A'
};
const item2 = {
  color: '#FF8C75'
};
const item3 = {
  color: '#FFB499'
};
const data = DATA_HERE;


option = {
  tooltip: {
        formatter: function(params) {
            return `${params.name}`;
        },
    },
  series: {
    radius: ['15%', '80%'],
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
      </script>
    </body>
</html>
"""


BASIC_STYLE = { "color": '#7dd491', "borderWidth": 2 }


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
            "vulnerabilities": set(),
            "max_vulnerability_severity": None,
            "visited": False}


def parse_file(input_file_path):
    print("Parsing input file...")
    with open(input_file_path, 'r') as file:
        data = json.load(file)

    components = {}

    for component in data["components"]:
        new_component = {"name": component["name"],
                         "version": component["version"] if "version" in component else "-",
                         "type": component["type"],
                         "depends_on": set(),
                         "dependency_of": set(),
                         "vulnerabilities": set(),
                         "max_vulnerability_severity": None,
                         "visited": False}

        if "bom-ref" in component:
            bom_ref = component["bom-ref"]
        else:
            print(f"WARNING: component with name '{component['name']}' does not have a 'bom-ref'. I'll create a fake one.")
            bom_ref = f"{hash(json.dumps(new_component, sort_keys=True, cls=SetEncoder))}"

        components[bom_ref] = new_component


    # sometimes dependencies are declared inside a component, I'll check that now

    for component in data["components"]:
        if "dependencies" in component:
            for dependency in component["dependencies"]:
                depends_on = dependency["ref"]
                if depends_on not in components:
                    print(f"WARNING: 'ref' '{depends_on}' is used in 'dependencies' inside a component but it's not declared in 'components'. I'll create a fake one.")
                    components[depends_on] = create_fake_component(depends_on)

                components[bom_ref]["depends_on"].add(depends_on)
                components[depends_on]["dependency_of"].add(bom_ref)


    if "dependencies" in data:
        for dependency in data["dependencies"]:
            bom_ref = dependency["ref"]
            if bom_ref not in components:
                print(f"WARNING: 'ref' '{bom_ref}' is used in 'dependencies' but it's not declared in 'components'. I'll create a fake one.")
                components[bom_ref] = create_fake_component(bom_ref)

            if "dependsOn" in dependency:
                for depends_on in dependency["dependsOn"]:
                    if depends_on not in components:
                        print(f"WARNING: 'dependsOn' '{depends_on}' is used in 'dependencies' but it's not declared in 'components'. I'll create a fake one.")
                        components[depends_on] = create_fake_component(depends_on)

                    components[bom_ref]["depends_on"].add(depends_on)
                    components[depends_on]["dependency_of"].add(bom_ref)

    if "vulnerabilities" in data:
        for vulnerability in data["vulnerabilities"]:
            vuln_id = vulnerability["id"]

            vuln_rating = None
            available_rating_methods = set()
            for rating in vulnerability["ratings"]:
                available_rating_methods.add(rating["method"])

            # TODO qui scelgo il metodo di rating che mi piace di più e poi estraggo i suoi valori

            for affects in vulnerability["affects"]:
                bom_ref = affects["ref"]
                if bom_ref not in components:
                    print(f"WARNING: 'ref' '{bom_ref}' is used in 'vulnerabilities' but it's not declared in 'components'. I'll create a fake one.")
                    components[bom_ref] = create_fake_component(bom_ref)

                # TODO qui associo la vuln al componente

    return components


def get_children(components, component, parents):
    children = []
    value = 0
    for depends_on in component["depends_on"]:
        if components[depends_on]["version"] != "-":
            child_name = f'{components[depends_on]["name"]} <b>{components[depends_on]["version"]}</b>'
        else:
            child_name = f'{components[depends_on]["name"]}'
        child_component = components[depends_on]
        child_component["visited"] = True
        if depends_on not in parents:  # this is done to avoid infinite recursion in case of circular dependencies
            parents.append(depends_on)
            child_children, children_value = get_children(components, child_component, parents)
            value += children_value
            children.append({"name": child_name,
                             "children": child_children,
                             "value": children_value,
                             "itemStyle": BASIC_STYLE
                             })
        else:
            value += 1
            children.append({"name": child_name,
                             "children": [],
                             "value": 1,
                             "itemStyle": BASIC_STYLE
                             })

    if value == 0:
        value = 1

    return children, value


def add_root_component(components, component, data, bom_ref):
    component["visited"] = True
    parents = [bom_ref]
    if component["version"] != "-":
        root_name = f'{component["name"]} <b>{component["version"]}</b>'
    else:
        root_name = f'{component["name"]}'
    root_children, root_value = get_children(components, component, parents)

    new_element = {"name": root_name,
                   "children": root_children,
                   "value": root_value,
                   "itemStyle": BASIC_STYLE
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


def write_output_file(html_content, output_file_path):
    with open(output_file_path, "w") as text_file:
        text_file.write(html_content)


def main(input_file_path, output_file_path):
    if not os.path.exists(input_file_path):
        print(f"File does not exist: '{input_file_path}'")
        exit()

    components = parse_file(input_file_path)
    """try:
        components = parse_file(input_file_path)
    except Exception as e:
        print("Error parsing input file!")
        exit()"""

    echart_data = build_echarts_data(components)
    double_check_if_all_components_were_taken_into_account(components, echart_data)
    
    html_content = HTML_TEMPLATE.replace("DATA_HERE", json.dumps(echart_data, indent=2))
    write_output_file(html_content, output_file_path)
    print("Done.")
        


if __name__ == "__main__":
    print(f'''
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
    main(input_file_path, output_file_path)
