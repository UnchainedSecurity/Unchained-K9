import React, { useState, useEffect, useMemo, useRef } from 'react';
import { Tree } from 'react-arborist';
import { Panel, Group as PanelGroup, Separator as PanelResizeHandle } from 'react-resizable-panels';
import { Search, ShieldAlert, Settings, Database, File, FileCode, FileText, Folder, FolderOpen, Info } from 'lucide-react';
import { SeverityBadge } from './SeverityBadge'; // We will extract this too

export default function AttackSurfaceMap({ data, selectedNodeId }) {
  const [term, setTerm] = useState('');
  const [selectedNode, setSelectedNode] = useState(null);
  const treeRef = useRef(null);

  // We need to adapt our flat-ish tree structure to something react-arborist likes better,
  // or just use it natively if it matches.
  // react-arborist expects id, name, children.
  
  const filterTree = (nodes, searchTerm) => {
    if (!searchTerm) return nodes;
    return nodes.reduce((acc, node) => {
      const match = node.name.toLowerCase().includes(searchTerm.toLowerCase());
      const children = filterTree(node.children || [], searchTerm);
      if (match || children.length > 0) {
         acc.push({ ...node, children });
      }
      return acc;
    }, []);
  };

  const filteredData = useMemo(() => filterTree(data, term), [data, term]);

  useEffect(() => {
     if (selectedNodeId && treeRef.current) {
        // Arborist gives us an API to open nodes
        treeRef.current.select(selectedNodeId);
        
        // Find the node data to show in the details pane
        let foundNode = null;
        const findNode = (nodes) => {
          for (const n of nodes) {
            if (n.id === selectedNodeId) foundNode = n;
            if (n.children) findNode(n.children);
          }
        }
        findNode(data);
        if (foundNode) setSelectedNode(foundNode);
     }
  }, [selectedNodeId, data]);

  const NodeRenderer = ({ node, style, dragHandle }) => {
      const isDir = node.data.is_dir || node.children?.length > 0;
      const isOpen = node.isOpen;
      const isSelected = node.isSelected;
      
      const sevColors = {
        Critical: 'text-red-500', High: 'text-orange-500', Medium: 'text-yellow-500',
        Low: 'text-blue-500', Info: 'text-cyan-500', None: 'text-slate-400'
      };
      const colorClass = sevColors[node.data.severity] || 'text-slate-400';
      
      let Icon = File;
      if (isDir) Icon = isOpen ? FolderOpen : Folder;
      else if (String(node.data.name).match(/\.(js|jsx|ts)$/i)) Icon = FileCode;
      else if (String(node.data.name).match(/\.(json|xml|yaml)$/i)) Icon = FileText;
      else if (String(node.data.name).match(/\.(env|config)/i)) Icon = Settings;
      else if (String(node.data.name).match(/\.(sql|db|sqlite)/i)) Icon = Database;

      return (
        <div 
          style={style}
          ref={dragHandle}
          onClick={() => {
             node.toggle();
             setSelectedNode(node.data);
          }}
          className={`flex items-center gap-2 cursor-pointer hover:bg-white/5 py-1 pr-2 rounded transition-colors ${isSelected ? 'bg-white/10 ring-1 ring-white/20' : ''}`}
        >
          <span className="text-slate-500 text-[10px] w-3 flex justify-center shrink-0" onClick={(e) => { e.stopPropagation(); node.toggle() }}>
            {isDir ? (isOpen ? '▼' : '▶') : ''}
          </span>
          <Icon className={`w-4 h-4 ${colorClass} shrink-0`} />
          <span className={`text-sm ${colorClass} font-medium truncate`}>{node.data.name}</span>
          {node.data.finding && <ShieldAlert className="w-3 h-3 text-red-500 ml-auto shrink-0" />}
        </div>
      );
  };

  if (!data || data.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-500 rounded-3xl border border-white/10 bg-white/5 shadow-2xl backdrop-blur-xl">
        No attack surface data available. Wait for a scan to complete.
      </div>
    );
  }

  return (
    <div className="h-[700px] flex flex-col rounded-3xl border border-white/10 bg-white/5 shadow-2xl backdrop-blur-xl overflow-hidden">
      <div className="p-4 border-b border-white/10 flex items-center gap-4 bg-black/20">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input 
            type="text" 
            placeholder="Search paths..." 
            value={term}
            onChange={e => setTerm(e.target.value)}
            className="w-full bg-black/40 border border-white/10 rounded-xl pl-9 pr-3 py-1.5 text-sm text-white outline-none focus:border-red-600/50"
          />
        </div>
      </div>
      
      <div className="flex-1 flex overflow-hidden">
        <PanelGroup direction="horizontal">
            <Panel defaultSize={70} minSize={20} className="h-full bg-black/30 p-2 border-r border-white/10">
                <Tree
                    ref={treeRef}
                    data={filteredData}
                    openByDefault={true}
                    width="100%"
                    height={600}
                    indent={16}
                    rowHeight={28}
                    searchTerm={term}
                    searchMatch={(node, term) => node.data.name.toLowerCase().includes(term.toLowerCase())}
                >
                    {NodeRenderer}
                </Tree>
            </Panel>
            
            <PanelResizeHandle className="w-1 bg-white/10 hover:bg-white/20 transition-colors cursor-col-resize" />

            <Panel defaultSize={30} minSize={15} className="h-full bg-slate-950/50 p-6 overflow-y-auto">
              {!selectedNode ? (
                <div className="flex flex-col items-center justify-center h-full text-slate-500">
                  <Info className="w-12 h-12 mb-4 opacity-20" />
                  <p>Select a node in the tree to view details</p>
                </div>
              ) : (
                <div className="space-y-6">
                  <div>
                    <h3 className="text-xl font-bold text-white mb-1 break-all">{selectedNode.name}</h3>
                    <p className="text-sm font-mono text-slate-400 break-all">{selectedNode.id}</p>
                  </div>
                  
                  <div className="flex gap-2">
                    <SeverityBadge severity={selectedNode.severity} />
                    {selectedNode.is_dir && <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-white/5 text-slate-300 border border-white/10">Directory</span>}
                  </div>
                  
                  {selectedNode.finding && (
                    <div className="bg-red-950/20 border border-red-500/20 rounded-xl p-5">
                      <div className="flex items-center gap-2 mb-4">
                        <ShieldAlert className="w-5 h-5 text-red-500" />
                        <h4 className="font-semibold text-white">Vulnerability Finding</h4>
                      </div>
                      
                      <div className="space-y-4">
                        <div>
                          <div className="text-xs text-slate-400 mb-1 uppercase tracking-wider">Type</div>
                          <div className="text-sm text-slate-200">{selectedNode.finding.type}</div>
                        </div>
                        <div>
                          <div className="text-xs text-slate-400 mb-1 uppercase tracking-wider">Matched Value</div>
                          <div className="text-sm font-mono text-slate-300 break-all bg-black/40 p-2 rounded border border-white/5">{selectedNode.finding.value}</div>
                        </div>
                        <div className="flex gap-4">
                          <div>
                            <div className="text-xs text-slate-400 mb-1 uppercase tracking-wider">Severity</div>
                            <div className="text-sm text-slate-200">{selectedNode.finding.severity}</div>
                          </div>
                          <div>
                            <div className="text-xs text-slate-400 mb-1 uppercase tracking-wider">Status</div>
                            <div className="text-sm text-slate-200">{selectedNode.finding.status}</div>
                          </div>
                        </div>
                        {selectedNode.finding.fp_reason && (
                          <div className="bg-orange-950/30 border border-orange-500/30 rounded p-3 text-sm text-orange-200 mt-2">
                            <strong>Flagged as FP:</strong> {selectedNode.finding.fp_reason}
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                  
                  {!selectedNode.finding && selectedNode.is_dir && (
                    <div className="bg-white/5 border border-white/10 rounded-xl p-5">
                      <p className="text-sm text-slate-300">
                        This is a directory node. Inherited severity corresponds to the highest severity finding found within its children.
                      </p>
                    </div>
                  )}
                </div>
              )}
            </Panel>
        </PanelGroup>
      </div>
    </div>
  );
}
