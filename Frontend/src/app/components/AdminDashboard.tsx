import { useNavigate } from 'react-router-dom';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts';
import { Activity, Cpu, Database, Shield, Users, CheckCircle, XCircle, ArrowLeft } from 'lucide-react';

const performanceData = [
  { time: '00:00', precision: 0.94, recall: 0.91 },
  { time: '04:00', precision: 0.96, recall: 0.93 },
  { time: '08:00', precision: 0.95, recall: 0.94 },
  { time: '12:00', precision: 0.97, recall: 0.95 },
  { time: '16:00', precision: 0.96, recall: 0.94 },
  { time: '20:00', precision: 0.98, recall: 0.96 },
];

const resourceData = [
  { time: '00:00', gpu: 45, cpu: 32 },
  { time: '04:00', gpu: 52, cpu: 38 },
  { time: '08:00', gpu: 78, cpu: 65 },
  { time: '12:00', gpu: 85, cpu: 72 },
  { time: '16:00', gpu: 68, cpu: 54 },
  { time: '20:00', gpu: 42, cpu: 30 },
];

const pseudoLabels = [
  { id: 1, filename: 'sample_001.exe', confidence: 0.96, prediction: 'Malicious', status: 'pending' },
  { id: 2, filename: 'sample_002.dll', confidence: 0.89, prediction: 'Benign', status: 'pending' },
  { id: 3, filename: 'sample_003.bin', confidence: 0.92, prediction: 'Malicious', status: 'pending' },
  { id: 4, filename: 'sample_004.elf', confidence: 0.88, prediction: 'Benign', status: 'pending' },
];

const userLogs = [
  { id: 1, user: 'analyst_01', action: 'File Analysis', timestamp: '2026-01-03 14:23:15', ip: '192.168.1.10' },
  { id: 2, user: 'analyst_02', action: 'Export Report', timestamp: '2026-01-03 14:15:42', ip: '192.168.1.11' },
  { id: 3, user: 'admin_user', action: 'Model Update', timestamp: '2026-01-03 13:58:30', ip: '192.168.1.5' },
  { id: 4, user: 'analyst_01', action: 'File Upload', timestamp: '2026-01-03 13:45:12', ip: '192.168.1.10' },
];

export function AdminDashboard() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="bg-card border-b border-border px-8 py-4">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/dashboard')}
            className="text-muted-foreground hover:text-foreground transition-colors"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-destructive/20 rounded-lg flex items-center justify-center">
              <Shield className="w-6 h-6 text-destructive" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-foreground">Admin Dashboard</h1>
              <p className="text-xs text-muted-foreground">System Health & Management</p>
            </div>
          </div>
        </div>
      </header>

      <div className="p-8 space-y-8">
        {/* System Metrics KPIs */}
        <div className="grid grid-cols-4 gap-6">
          <div className="bg-card border border-border rounded-lg p-6">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm text-muted-foreground">GPU Load</h3>
              <Cpu className="w-5 h-5 text-accent" />
            </div>
            <p className="text-3xl font-bold text-foreground">68%</p>
            <p className="text-xs text-muted-foreground mt-1">MIL Inference</p>
          </div>

          <div className="bg-card border border-border rounded-lg p-6">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm text-muted-foreground">CPU Load</h3>
              <Activity className="w-5 h-5 text-primary" />
            </div>
            <p className="text-3xl font-bold text-foreground">54%</p>
            <p className="text-xs text-muted-foreground mt-1">Average utilization</p>
          </div>

          <div className="bg-card border border-border rounded-lg p-6">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm text-muted-foreground">Active Users</h3>
              <Users className="w-5 h-5 text-primary" />
            </div>
            <p className="text-3xl font-bold text-foreground">24</p>
            <p className="text-xs text-muted-foreground mt-1">Currently online</p>
          </div>

          <div className="bg-card border border-border rounded-lg p-6">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm text-muted-foreground">Dataset Size</h3>
              <Database className="w-5 h-5 text-accent" />
            </div>
            <p className="text-3xl font-bold text-foreground">45K</p>
            <p className="text-xs text-muted-foreground mt-1">Training samples</p>
          </div>
        </div>

        {/* Charts Row */}
        <div className="grid grid-cols-2 gap-6">
          {/* GPU/CPU Load Chart */}
          <div className="bg-card border border-border rounded-lg p-6">
            <h2 className="text-lg font-semibold text-foreground mb-4">Resource Utilization (24h)</h2>
            <ResponsiveContainer width="100%" height={250}>
              <AreaChart data={resourceData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                <XAxis dataKey="time" stroke="#888" />
                <YAxis stroke="#888" />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1E1E1E', border: '1px solid #333', borderRadius: '8px' }}
                  labelStyle={{ color: '#E0E0E0' }}
                />
                <Area type="monotone" dataKey="gpu" stroke="#FFA500" fill="#FFA500" fillOpacity={0.3} />
                <Area type="monotone" dataKey="cpu" stroke="#00FF41" fill="#00FF41" fillOpacity={0.3} />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Model Performance Chart */}
          <div className="bg-card border border-border rounded-lg p-6">
            <h2 className="text-lg font-semibold text-foreground mb-4">Model Performance (Precision/Recall)</h2>
            <ResponsiveContainer width="100%" height={250}>
              <LineChart data={performanceData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                <XAxis dataKey="time" stroke="#888" />
                <YAxis domain={[0.85, 1]} stroke="#888" />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1E1E1E', border: '1px solid #333', borderRadius: '8px' }}
                  labelStyle={{ color: '#E0E0E0' }}
                />
                <Line type="monotone" dataKey="precision" stroke="#00FF41" strokeWidth={2} dot={{ fill: '#00FF41' }} />
                <Line type="monotone" dataKey="recall" stroke="#00D4FF" strokeWidth={2} dot={{ fill: '#00D4FF' }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Dataset Management */}
        <div className="bg-card border border-border rounded-lg p-6">
          <h2 className="text-lg font-semibold text-foreground mb-4">Dataset Management - Pseudo-labeled Samples</h2>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left py-3 px-4 text-sm text-muted-foreground">Filename</th>
                  <th className="text-left py-3 px-4 text-sm text-muted-foreground">Confidence</th>
                  <th className="text-left py-3 px-4 text-sm text-muted-foreground">Prediction</th>
                  <th className="text-left py-3 px-4 text-sm text-muted-foreground">Actions</th>
                </tr>
              </thead>
              <tbody>
                {pseudoLabels.map((item) => (
                  <tr key={item.id} className="border-b border-border hover:bg-secondary/50 transition-colors">
                    <td className="py-3 px-4">
                      <span className="text-foreground font-mono text-sm">{item.filename}</span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-foreground font-mono">{(item.confidence * 100).toFixed(1)}%</span>
                    </td>
                    <td className="py-3 px-4">
                      <span className={`text-sm font-semibold ${item.prediction === 'Malicious' ? 'text-destructive' : 'text-primary'}`}>
                        {item.prediction}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <button className="text-primary hover:text-primary/80 flex items-center gap-1 text-sm">
                          <CheckCircle className="w-4 h-4" />
                          Approve
                        </button>
                        <button className="text-destructive hover:text-destructive/80 flex items-center gap-1 text-sm">
                          <XCircle className="w-4 h-4" />
                          Reject
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* User Access Logs */}
        <div className="bg-card border border-border rounded-lg p-6">
          <h2 className="text-lg font-semibold text-foreground mb-4">User Access Logs</h2>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left py-3 px-4 text-sm text-muted-foreground">User</th>
                  <th className="text-left py-3 px-4 text-sm text-muted-foreground">Action</th>
                  <th className="text-left py-3 px-4 text-sm text-muted-foreground">Timestamp</th>
                  <th className="text-left py-3 px-4 text-sm text-muted-foreground">IP Address</th>
                </tr>
              </thead>
              <tbody>
                {userLogs.map((log) => (
                  <tr key={log.id} className="border-b border-border hover:bg-secondary/50 transition-colors">
                    <td className="py-3 px-4">
                      <span className="text-foreground font-mono text-sm">{log.user}</span>
                    </td>
                    <td className="py-3 px-4 text-sm text-foreground">{log.action}</td>
                    <td className="py-3 px-4 text-sm text-muted-foreground font-mono">{log.timestamp}</td>
                    <td className="py-3 px-4 text-sm text-muted-foreground font-mono">{log.ip}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
