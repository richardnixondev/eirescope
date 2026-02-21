/* EireScope — D3.js Entity Relationship Graph Visualization */

(function() {
    if (typeof investigationData === 'undefined' || !investigationData.graph) return;

    const graph = investigationData.graph;
    if (!graph.nodes.length) return;

    const container = document.getElementById('entity-graph');
    if (!container) return;

    const width = container.clientWidth;
    const height = container.clientHeight || 500;

    // Color mapping for entity types
    const typeColors = {
        email: '#8b5cf6',
        username: '#3b82f6',
        phone: '#10b981',
        ip_address: '#f59e0b',
        domain: '#06b6d4',
        social_profile: '#ec4899',
        breach: '#ef4444',
        whois_info: '#a78bfa',
        geo_location: '#34d399',
        carrier_info: '#fbbf24',
        dns_record: '#67e8f9',
        company: '#f472b6',
        person: '#c084fc',
        url: '#38bdf8',
        hash: '#fb923c'
    };

    // Node size by type importance
    const typeSizes = {
        email: 14, username: 14, phone: 14, ip_address: 12,
        domain: 12, social_profile: 8, breach: 10, whois_info: 8,
        geo_location: 9, carrier_info: 8, dns_record: 7, url: 7
    };

    const svg = d3.select(container)
        .append('svg')
        .attr('width', width)
        .attr('height', height)
        .attr('viewBox', [0, 0, width, height]);

    // Background
    svg.append('rect')
        .attr('width', width)
        .attr('height', height)
        .attr('fill', '#1a2332');

    // Zoom behavior
    const g = svg.append('g');
    const zoom = d3.zoom()
        .scaleExtent([0.3, 5])
        .on('zoom', (event) => g.attr('transform', event.transform));
    svg.call(zoom);

    // Build simulation
    const simulation = d3.forceSimulation(graph.nodes)
        .force('link', d3.forceLink(graph.links).id(d => d.id).distance(100))
        .force('charge', d3.forceManyBody().strength(-200))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(d => (typeSizes[d.type] || 8) + 5));

    // Links
    const link = g.append('g')
        .selectAll('line')
        .data(graph.links)
        .join('line')
        .attr('stroke', '#2d3748')
        .attr('stroke-width', d => Math.max(1, d.confidence * 2))
        .attr('stroke-opacity', 0.6);

    // Link labels
    const linkLabel = g.append('g')
        .selectAll('text')
        .data(graph.links)
        .join('text')
        .text(d => d.type.replace(/_/g, ' '))
        .attr('font-size', '8px')
        .attr('fill', '#4a5568')
        .attr('text-anchor', 'middle')
        .attr('dy', -4);

    // Nodes
    const node = g.append('g')
        .selectAll('g')
        .data(graph.nodes)
        .join('g')
        .call(d3.drag()
            .on('start', dragStarted)
            .on('drag', dragged)
            .on('end', dragEnded));

    // Node circles
    node.append('circle')
        .attr('r', d => typeSizes[d.type] || 8)
        .attr('fill', d => typeColors[d.type] || '#666')
        .attr('stroke', '#0a0e17')
        .attr('stroke-width', 2)
        .attr('opacity', 0.9);

    // Glow effect for seed entity (first node)
    node.filter((d, i) => i === 0)
        .select('circle')
        .attr('stroke', '#fff')
        .attr('stroke-width', 3)
        .attr('r', 18);

    // Node labels
    node.append('text')
        .text(d => d.label.length > 25 ? d.label.substring(0, 25) + '...' : d.label)
        .attr('x', d => (typeSizes[d.type] || 8) + 6)
        .attr('y', 4)
        .attr('font-size', '11px')
        .attr('fill', '#cbd5e1')
        .attr('font-family', "'JetBrains Mono', monospace");

    // Tooltip
    const tooltip = d3.select(container)
        .append('div')
        .style('position', 'absolute')
        .style('background', '#1e293b')
        .style('border', '1px solid #334155')
        .style('border-radius', '8px')
        .style('padding', '10px 14px')
        .style('font-size', '12px')
        .style('color', '#e2e8f0')
        .style('pointer-events', 'none')
        .style('opacity', 0)
        .style('z-index', 10)
        .style('max-width', '300px');

    node.on('mouseover', function(event, d) {
        tooltip.transition().duration(200).style('opacity', 1);
        tooltip.html(`
            <div style="font-weight:700;margin-bottom:4px;color:${typeColors[d.type] || '#fff'}">${d.type.toUpperCase()}</div>
            <div style="font-family:monospace;word-break:break-all">${d.label}</div>
            <div style="margin-top:4px;color:#94a3b8">Source: ${d.source}</div>
            <div style="color:#94a3b8">Confidence: ${Math.round(d.confidence * 100)}%</div>
        `)
        .style('left', (event.offsetX + 15) + 'px')
        .style('top', (event.offsetY - 10) + 'px');

        d3.select(this).select('circle')
            .transition().duration(200)
            .attr('r', (typeSizes[d.type] || 8) * 1.4);
    })
    .on('mouseout', function(event, d) {
        tooltip.transition().duration(200).style('opacity', 0);
        const isFirst = graph.nodes.indexOf(d) === 0;
        d3.select(this).select('circle')
            .transition().duration(200)
            .attr('r', isFirst ? 18 : (typeSizes[d.type] || 8));
    });

    // Simulation tick
    simulation.on('tick', () => {
        link
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);

        linkLabel
            .attr('x', d => (d.source.x + d.target.x) / 2)
            .attr('y', d => (d.source.y + d.target.y) / 2);

        node.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    // Drag functions
    function dragStarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x; d.fy = d.y;
    }
    function dragged(event, d) {
        d.fx = event.x; d.fy = event.y;
    }
    function dragEnded(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null; d.fy = null;
    }

    // Fit to view on load
    setTimeout(() => {
        const bounds = g.node().getBBox();
        const dx = bounds.width, dy = bounds.height;
        const x = bounds.x + dx / 2, y = bounds.y + dy / 2;
        const scale = 0.85 / Math.max(dx / width, dy / height);
        const translate = [width / 2 - scale * x, height / 2 - scale * y];
        svg.transition().duration(750)
            .call(zoom.transform, d3.zoomIdentity.translate(translate[0], translate[1]).scale(scale));
    }, 2000);
})();
