class IntelligenceGraph {
    constructor(containerId) {
        this.container = document.getElementById(containerId);

        // Define default options for Vis.js
        this.options = {
            nodes: {
                shape: 'dot',
                size: 20,
                font: {
                    color: '#c9d1d9',
                    face: 'Inter'
                },
                borderWidth: 2,
                shadow: true
            },
            edges: {
                width: 2,
                shadow: true,
                color: { color: '#58a6ff', highlight: '#3182ce' },
                smooth: { type: 'continuous' }
            },
            physics: {
                forceAtlas2Based: {
                    gravitationalConstant: -26,
                    centralGravity: 0.005,
                    springLength: 230,
                    springConstant: 0.18
                },
                maxVelocity: 146,
                solver: 'forceAtlas2Based',
                timestep: 0.35,
                stabilization: { iterations: 150 }
            },
            interaction: {
                hover: true,
                navigationButtons: true,
                keyboard: true
            }
        };

        this.network = null;
        this.nodes = new vis.DataSet();
        this.edges = new vis.DataSet();
    }

    init() {
        const data = { nodes: this.nodes, edges: this.edges };
        this.network = new vis.Network(this.container, data, this.options);
    }

    clear() {
        this.nodes.clear();
        this.edges.clear();
    }

    updateFromResults(target, targetType, rawResults) {
        console.log("Drawing graph for", target, rawResults);
        this.clear();

        // Add root node
        const rootId = `root_${target}`;
        this.nodes.add({
            id: rootId,
            label: target,
            title: `Target: ${target}`,
            color: { background: '#da3633', border: '#b32c2a' },
            size: 30
        });

        // Loop through module results to build the graph
        if (!rawResults || !Array.isArray(rawResults)) return;

        rawResults.forEach((res, index) => {
            const moduleName = res.module;
            const data = res.data;
            if (data.error) return;

            // Module Node
            const moduleId = `mod_${index}`;
            this.nodes.add({
                id: moduleId,
                label: moduleName.replace('_', ' '),
                color: { background: '#238636', border: '#1a6327' },
                size: 25
            });
            this.edges.add({ from: rootId, to: moduleId, value: 2 });

            // Extract Data points
            if (moduleName === 'GeoIP') {
                const infoId = `info_${index}`;
                this.nodes.add({
                    id: infoId,
                    label: `${data.city || 'Unknown'}\n${data.country || ''}`,
                    title: `ISP: ${data.isp}\nLat: ${data.lat}, Lon: ${data.lon}`,
                    shape: 'box',
                    color: { background: '#30363d', border: '#58a6ff' }
                });
                this.edges.add({ from: moduleId, to: infoId });
            }
            else if (moduleName === 'Subdomain_Scanner') {
                const subdomains = data.subdomains || [];
                // Only show top 10 max to prevent graph explosion
                const limit = Math.min(10, subdomains.length);
                for (let i = 0; i < limit; i++) {
                    const subId = `sub_${index}_${i}`;
                    this.nodes.add({
                        id: subId,
                        label: subdomains[i],
                        shape: 'hexagon',
                        size: 15,
                        color: { background: '#8b949e', border: '#c9d1d9' }
                    });
                    this.edges.add({ from: moduleId, to: subId });
                }
                if (subdomains.length > 10) {
                    this.nodes.add({
                        id: `sub_${index}_more`,
                        label: `+${subdomains.length - 10} more...`,
                        shape: 'text',
                        font: { color: '#8b949e' }
                    });
                    this.edges.add({ from: moduleId, to: `sub_${index}_more`, dashes: true });
                }
            }
            else if (moduleName === 'Username_Checker') {
                const details = data.details || {};
                let count = 0;
                for (const [platform, status] of Object.entries(details)) {
                    if (status === 'Found') {
                        const platId = `plat_${index}_${count}`;
                        this.nodes.add({
                            id: platId,
                            label: platform,
                            shape: 'ellipse',
                            color: { background: '#d29922', border: '#9e6a03' }
                        });
                        this.edges.add({ from: moduleId, to: platId });
                        count++;
                    }
                }
            }
            // Add other modules here generically
            else {
                const infoId = `gen_${index}`;
                this.nodes.add({
                    id: infoId,
                    label: "Data Extracted",
                    shape: 'box'
                });
                this.edges.add({ from: moduleId, to: infoId });
            }
        });

        // Apply stabilization
        this.network.stabilize();
    }
}

window.IntelligenceGraph = IntelligenceGraph;
