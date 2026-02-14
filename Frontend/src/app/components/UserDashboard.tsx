import { useNavigate } from 'react-router-dom';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { FileText, AlertTriangle, Clock, Upload, Eye } from 'lucide-react';

const trendData = [
  { month: 'Jan', Ransomware: 12, Trojan: 8 },
  { month: 'Feb', Ransomware: 19, Trojan: 14 },
  { month: 'Mar', Ransomware: 15, Trojan: 18 },
  { month: 'Apr', Ransomware: 25, Trojan: 12 },
  { month: 'May', Ransomware: 22, Trojan: 20 },
  { month: 'Jun', Ransomware: 30, Trojan: 25 },
];

const analysisHistory = [
  { id: 1, name: 'malware_sample_1.exe', hash: '3f8a9c2d...', date: '2026-01-02', status: 'Malicious', score: 98 },
  { id: 2, name: 'update_installer.dll', hash: '7b2e1f5a...', date: '2026-01-02', status: 'Benign', score: 5 },
  { id: 3, name: 'trojan_variant.bin', hash: '9d4c3a8e...', date: '2026-01-01', status: 'Malicious', score: 95 },
  { id: 4, name: 'system_cleaner.exe', hash: '2a5f8c1b...', date: '2026-01-01', status: 'Suspicious', score: 67 },
  { id: 5, name: 'crypto_miner.elf', hash: '6e9d2a4f...', date: '2025-12-31', status: 'Malicious', score: 89 },
];

export function UserDashboard() {
  const navigate = useNavigate();

  const getStatusColor = (status: string) => {
    if (status === 'Malicious') return 'text-destructive';
    if (status === 'Benign') return 'text-primary';
    return 'text-accent';
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-destructive';
    if (score >= 50) return 'text-accent';
    return 'text-primary';
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="bg-card border-b border-border px-8 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-primary/20 rounded-lg flex items-center justify-center">
              <FileText className="w-6 h-6 text-primary" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-foreground">MIL-Malware Analyzer</h1>
              <p className="text-xs text-muted-foreground">Analysis Dashboard</p>
            </div>
          </div>
          <button
            onClick={() => navigate('/upload')}
            className="bg-primary text-primary-foreground px-6 py-2 rounded-md hover:opacity-90 transition-opacity flex items-center gap-2"
          >
            <Upload className="w-4 h-4" />
            New Analysis
          </button>
        </div>
      </header>

      <div className="p-8 space-y-8">
        {/* KPIs */}
        <div className="grid grid-cols-3 gap-6">
          <div className="bg-card border border-border rounded-lg p-6">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm text-muted-foreground">Total Files</h3>
              <FileText className="w-5 h-5 text-primary" />
            </div>
            <p className="text-3xl font-bold text-foreground">1,247</p>
            <p className="text-xs text-muted-foreground mt-1">+12% from last month</p>
          </div>

          <div className="bg-card border border-border rounded-lg p-6">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm text-muted-foreground">High Risk Detected</h3>
              <AlertTriangle className="w-5 h-5 text-destructive" />
            </div>
            <p className="text-3xl font-bold text-destructive">247</p>
            <p className="text-xs text-muted-foreground mt-1">19.8% detection rate</p>
          </div>

          <div className="bg-card border border-border rounded-lg p-6">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm text-muted-foreground">Avg. Analysis Time</h3>
              <Clock className="w-5 h-5 text-accent" />
            </div>
            <p className="text-3xl font-bold text-foreground">2.4s</p>
            <p className="text-xs text-muted-foreground mt-1">-15% faster</p>
          </div>
        </div>

        {/* Chart */}
        <div className="bg-card border border-border rounded-lg p-6">
          <h2 className="text-lg font-semibold text-foreground mb-4">Threat Families Detected Over Time</h2>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={trendData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#333" />
              <XAxis dataKey="month" stroke="#888" />
              <YAxis stroke="#888" />
              <Tooltip
                contentStyle={{ backgroundColor: '#1E1E1E', border: '1px solid #333', borderRadius: '8px' }}
                labelStyle={{ color: '#E0E0E0' }}
              />
              <Legend />
              <Line type="monotone" dataKey="Ransomware" stroke="#FF3131" strokeWidth={2} dot={{ fill: '#FF3131' }} />
              <Line type="monotone" dataKey="Trojan" stroke="#FFA500" strokeWidth={2} dot={{ fill: '#FFA500' }} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Recent Analysis Table */}
        <div className="bg-card border border-border rounded-lg p-6">
          <h2 className="text-lg font-semibold text-foreground mb-4">Recent Analysis</h2>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left py-3 px-4 text-sm text-muted-foreground">File Name</th>
                  <th className="text-left py-3 px-4 text-sm text-muted-foreground">Hash</th>
                  <th className="text-left py-3 px-4 text-sm text-muted-foreground">Date</th>
                  <th className="text-left py-3 px-4 text-sm text-muted-foreground">Status</th>
                  <th className="text-left py-3 px-4 text-sm text-muted-foreground">ML Score</th>
                  <th className="text-left py-3 px-4 text-sm text-muted-foreground">Actions</th>
                </tr>
              </thead>
              <tbody>
                {analysisHistory.map((item) => (
                  <tr
                    key={item.id}
                    className="border-b border-border hover:bg-secondary/50 transition-colors cursor-pointer"
                    onClick={() => navigate('/analysis')}
                  >
                    <td className="py-3 px-4">
                      <span className="text-foreground font-mono text-sm">{item.name}</span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-muted-foreground font-mono text-sm">{item.hash}</span>
                    </td>
                    <td className="py-3 px-4 text-sm text-muted-foreground">{item.date}</td>
                    <td className="py-3 px-4">
                      <span className={`text-sm font-semibold ${getStatusColor(item.status)}`}>
                        {item.status}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span className={`text-sm font-bold ${getScoreColor(item.score)}`}>
                        {item.score}%
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <button className="text-primary hover:text-primary/80 flex items-center gap-1 text-sm">
                        <Eye className="w-4 h-4" />
                        View
                      </button>
                    </td>
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
