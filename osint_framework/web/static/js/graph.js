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
        this._attachInteractionHandlers();
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
            this._addNode({
                id: moduleId,
                label: moduleName.replace('_', ' '),
                color: { background: '#238636', border: '#1a6327' },
                size: 25
            });
            this.edges.add({ from: rootId, to: moduleId, value: 2 });

            // Extract Data points
            if (moduleName === 'GeoIP') {
                const infoId = `info_${index}`;
                this._addNode({
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
                    this._addNode({
                        id: subId,
                        label: subdomains[i],
                        shape: 'hexagon',
                        size: 15,
                        color: { background: '#8b949e', border: '#c9d1d9' }
                    });
                    this.edges.add({ from: moduleId, to: subId });
                }
                if (subdomains.length > 10) {
                    this._addNode({
                        id: `sub_${index}_more`,
                        label: `+${subdomains.length - 10} more...`,
                        shape: 'text',
                        font: { color: '#8b949e' }
                    });
                    this.edges.add({ from: moduleId, to: `sub_${index}_more`, dashes: true });
                }
            }
            else if (moduleName === 'Username_Checker') {
                const profiles = Array.isArray(data.profiles) ? data.profiles : [];
                let count = 0;

                if (profiles.length > 0) {
                    const limit = Math.min(15, profiles.length);
                    for (let i = 0; i < limit; i++) {
                        const profile = profiles[i] || {};
                        const platform = profile.site || `Profile ${i + 1}`;
                        const profileUrl = profile.url || null;
                        const platId = `plat_${index}_${count}`;
                        this._addNode({
                            id: platId,
                            label: platform,
                            shape: 'ellipse',
                            color: { background: '#d29922', border: '#9e6a03' },
                            title: profileUrl ? `${platform}\n${profileUrl}` : platform,
                            url: profileUrl
                        });
                        this.edges.add({ from: moduleId, to: platId });
                        count++;
                    }

                    if (profiles.length > limit) {
                        const moreId = `plat_${index}_more`;
                        this._addNode({
                            id: moreId,
                            label: `+${profiles.length - limit} more...`,
                            shape: 'text',
                            font: { color: '#8b949e' }
                        });
                        this.edges.add({ from: moduleId, to: moreId, dashes: true });
                    }
                } else {
                    const details = data.details || {};
                    for (const [platform, status] of Object.entries(details)) {
                        if (status === 'Found') {
                            const platId = `plat_${index}_${count}`;
                            this._addNode({
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
            }
            else if (moduleName === 'Person_Name_Search_Dorks') {
                const quickLinks = Array.isArray(data.quick_links) ? data.quick_links : [];
                const limit = Math.min(6, quickLinks.length);
                for (let i = 0; i < limit; i++) {
                    const item = quickLinks[i] || {};
                    const dorkId = `dork_${index}_${i}`;
                    this._addNode({
                        id: dorkId,
                        label: item.label || `Query ${i + 1}`,
                        shape: 'box',
                        color: { background: '#1f6feb', border: '#1158c7' },
                        title: item.google ? `${item.label}\nClick to open (Google)` : (item.label || ''),
                        url: item.google || null
                    });
                    this.edges.add({ from: moduleId, to: dorkId });
                }
            }
            // Add other modules here generically
            else {
                const infoId = `gen_${index}`;
                this._addNode({
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

    _attachInteractionHandlers() {
        if (!this.network || !this.container) return;

        this.network.on('click', (params) => {
            const nodeId = params?.nodes?.[0];
            if (!nodeId) return;
            const node = this.nodes.get(nodeId);
            if (!node || !node.url) return;
            window.open(node.url, '_blank', 'noopener,noreferrer');
        });

        this.network.on('hoverNode', (params) => {
            const node = this.nodes.get(params.node);
            this.container.style.cursor = node?.url ? 'pointer' : 'default';
        });

        this.network.on('blurNode', () => {
            this.container.style.cursor = 'default';
        });
    }

    _addNode(node) {
        const payload = { ...node };
        if (payload.url) {
            payload.title = payload.title
                ? `${payload.title}\nClick to open`
                : `Click to open\n${payload.url}`;
            payload.font = { ...(payload.font || {}), color: (payload.font && payload.font.color) || '#ffffff' };
            if (!payload.shape) payload.shape = 'box';
        }
        this.nodes.add(payload);
    }
}

window.IntelligenceGraph = IntelligenceGraph;
