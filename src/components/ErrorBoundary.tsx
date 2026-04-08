import * as React from 'react';
import { ErrorInfo, ReactNode } from 'react';
import { Card, CardHeader, CardTitle, CardContent, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { AlertCircle, RefreshCcw } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: string | null;
}

class ErrorBoundary extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
    };
  }

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error:', error, errorInfo);
    
    // Check if it's a Firestore error JSON string
    try {
      const parsed = JSON.parse(error.message);
      if (parsed.error && parsed.authInfo) {
        this.setState({ errorInfo: JSON.stringify(parsed, null, 2) });
      }
    } catch {
      // Not a JSON error
    }
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    window.location.reload();
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-zinc-950 flex items-center justify-center p-4">
          <Card className="max-w-2xl w-full border-red-900/50 bg-zinc-900/50 backdrop-blur-xl shadow-2xl">
            <CardHeader className="space-y-1">
              <div className="flex items-center space-x-2 text-red-500 mb-2">
                <AlertCircle className="w-6 h-6" />
                <CardTitle className="text-2xl font-bold">Something went wrong</CardTitle>
              </div>
              <p className="text-zinc-400">
                The application encountered an unexpected error. This might be due to a security rule violation or a network issue.
              </p>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/20">
                <p className="text-sm font-mono text-red-400 break-all">
                  {this.state.error?.message || 'Unknown error'}
                </p>
              </div>
              
              {this.state.errorInfo && (
                <div className="space-y-2">
                  <p className="text-xs font-medium text-zinc-500 uppercase tracking-wider">Diagnostic Information</p>
                  <pre className="p-4 rounded-xl bg-zinc-950 border border-zinc-800 text-[10px] font-mono text-zinc-400 overflow-auto max-h-60">
                    {this.state.errorInfo}
                  </pre>
                </div>
              )}
            </CardContent>
            <CardFooter className="flex justify-end border-t border-zinc-800 bg-zinc-900/30 pt-6">
              <Button 
                onClick={this.handleReset}
                className="bg-zinc-50 text-zinc-950 hover:bg-zinc-200 font-semibold"
              >
                <RefreshCcw className="w-4 h-4 mr-2" />
                Reload Application
              </Button>
            </CardFooter>
          </Card>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
