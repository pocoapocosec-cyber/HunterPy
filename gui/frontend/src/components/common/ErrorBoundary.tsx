import { Component, ErrorInfo, ReactNode } from 'react'
import { Alert } from '@components/ui/alert'

interface Props { children: ReactNode }
interface State { error: Error | null }

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }
  static getDerivedStateFromError(error: Error): State { return { error } }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('ErrorBoundary caught:', error, info)
  }
  render() {
    if (this.state.error) {
      return (
        <div className="p-6">
          <Alert tone="error" title="Something went wrong">
            {this.state.error.message}
          </Alert>
        </div>
      )
    }
    return this.props.children
  }
}
