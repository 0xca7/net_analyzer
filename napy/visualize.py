"""
    visualizes connections between individual
    hosts, using IPs
"""

import networkx as nx
import matplotlib.pyplot as plt

"""
visualizes network connections using
the networkx library
"""
class Visualizer:

    """
    create a new Visualizer instance with an empty graph
    """
    def __init__(self):
        self.G = nx.Graph()

    """
    add nodes to the graph, these are IP addresses
    """
    def add_nodes(self, nodes):
        for node in nodes:
            self.G.add_node(node)
    
    """
    add edges to the graph, these are destination and source IPs
    """
    def add_edges(self, edges):
        for edge in edges:
            self.G.add_edge(edge[0], edge[1])

    """
    write a plot of the graph to a file
    """
    def show(self, path):
        nx.draw(self.G, with_labels=True, font_weight='bold')
        filename = path + '/' + 'graph.png'
        plt.savefig(filename)
