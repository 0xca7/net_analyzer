"""
    visualizes connections between individual
    hosts, using IPs
"""

import pandas as pd
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
        nx.draw(self.G, with_labels=True, node_size=20, font_size=2)
        filename = path + '/' + 'graph.png'
        plt.savefig(filename, dpi=300)


"""list of nodes (1d list) and edges (list of tuples (src,dst))

reads the graph's edges from a csv, creates a list of nodes
and a list of edges as tuples
"""
def read_graph():

    nodes = set()
    edges = list()

    df = pd.read_csv('results/graph.csv')

    for (src,dst) in zip(df['src'], df['dst']):
        
        edges.append((src,dst))
        nodes.add(src)
        nodes.add(dst)

    return (list(nodes), edges)


"""None

reads the csv, builds the graph and creates
the plot
"""
if __name__ == '__main__':

    v = Visualizer()
    (nodes, edges) = read_graph()

    v.add_nodes(nodes)
    v.add_edges(edges)

    v.show('results')
