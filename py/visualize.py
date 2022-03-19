"""
    visualizes connections between individual
    hosts, using IPs
"""

from pyvis.network import Network

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
        nx.draw(self.G, with_labels=True, node_size=20, 
            font_size=2, node_color="tab:green", edge_color='tab:grey',
            width=0.25)
        filename = path + '/' + 'graph.png'
        plt.savefig(filename, dpi=1200)

    def interactive(self):
        nt = Network('1000px', '1000px')
        nt.from_nx(self.G)
        nt.show('nx.html')


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

    print('[+] reading graph data')
    (nodes, edges) = read_graph()

    print('[+] adding nodes')
    v.add_nodes(nodes)

    print('[+] adding edges')
    v.add_edges(edges)

    print('[+] writing result')
    v.show('results')

    print('[+] interactive')
    v.interactive()
    
