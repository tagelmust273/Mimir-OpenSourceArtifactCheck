"""Data visualization modules"""

import matplotlib.pyplot as plt
import networkx as nx
from io import BytesIO
from typing import Dict, List

# Configure matplotlib for non-interactive backend
plt.switch_backend('Agg')


class Visualization:
    """Create charts and graphs for analysis results"""

    @staticmethod
    async def create_threat_chart(threat_data: Dict) -> BytesIO:
        """
        Create threat distribution chart

        Args:
            threat_data: Dictionary with threat statistics

        Returns:
            BytesIO: PNG image buffer
        """
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

        # Pie chart - threat distribution
        labels = ['Malicious', 'Suspicious', 'Harmless', 'Undetected']
        sizes = [
            threat_data.get('malicious', 0),
            threat_data.get('suspicious', 0),
            threat_data.get('harmless', 0),
            threat_data.get('undetected', 0)
        ]
        colors = ['#FF4444', '#FFA500', '#00C851', '#9E9E9E']
        explode = (0.05, 0.05, 0, 0)

        ax1.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%',
                startangle=90, explode=explode)
        ax1.set_title('Threat Distribution', fontsize=14, fontweight='bold')

        # Bar chart - risk scores by service
        services = list(threat_data.get('services', {}).keys())
        scores = list(threat_data.get('services', {}).values())

        if services:
            bar_colors = ['#FF4444' if s > 50 else '#FFA500' if s > 0 else '#00C851' for s in scores]
            bars = ax2.bar(services, scores, color=bar_colors, edgecolor='black', linewidth=1)
            ax2.set_title('Risk Score by Service', fontsize=14, fontweight='bold')
            ax2.set_ylabel('Risk Score')
            ax2.set_ylim(0, 100)
            ax2.set_xlabel('Service')

            # Add value labels on bars
            for bar, score in zip(bars, scores):
                height = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width() / 2, height + 2,
                        f'{score}%', ha='center', va='bottom', fontsize=10)

        plt.tight_layout()

        buf = BytesIO()
        plt.savefig(buf, format='png', dpi=150, bbox_inches='tight', facecolor='white')
        plt.close()
        buf.seek(0)

        return buf

    @staticmethod
    async def create_relationship_graph(artifacts: List[Dict]) -> BytesIO:
        """
        Create relationship graph between artifacts

        Args:
            artifacts: List of artifacts with relationships

        Returns:
            BytesIO: PNG image buffer
        """
        plt.figure(figsize=(12, 8))
        G = nx.Graph()

        # Add nodes
        for artifact in artifacts:
            G.add_node(artifact['value'], type=artifact.get('type', 'unknown'))

        # Add edges if relationships exist
        for artifact in artifacts:
            for related in artifact.get('related', []):
                G.add_edge(artifact['value'], related.get('value', ''), 
                          relation=related.get('relation', 'related'))

        if len(G.nodes()) == 0:
            # Create dummy graph for single node
            G.add_node(artifacts[0]['value'], type=artifacts[0].get('type', 'unknown'))

        # Layout
        pos = nx.spring_layout(G, k=1.5, iterations=50)

        # Node colors based on type
        node_colors = []
        for node in G.nodes():
            node_type = G.nodes[node].get('type', 'unknown')
            if node_type == 'ip':
                node_colors.append('#4A90E2')  # Blue
            elif node_type == 'domain':
                node_colors.append('#50E3C2')  # Green
            elif node_type == 'hash':
                node_colors.append('#F5A623')  # Orange
            else:
                node_colors.append('#9B9B9B')  # Gray

        # Draw graph
        nx.draw(G, pos, with_labels=True, node_color=node_colors,
                node_size=2500, font_size=10, font_weight='bold',
                edge_color='#666666', width=1.5, alpha=0.8,
                font_color='white', font_family='sans-serif')

        # Add edge labels
        edge_labels = nx.get_edge_attributes(G, 'relation')
        nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=8)

        plt.title('Artifact Relationship Graph', fontsize=14, fontweight='bold')
        plt.axis('off')

        buf = BytesIO()
        plt.savefig(buf, format='png', dpi=150, bbox_inches='tight', facecolor='white')
        plt.close()
        buf.seek(0)

        return buf
