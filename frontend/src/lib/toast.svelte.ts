export type Toast = { id: number; text: string; kind: 'ok' | 'fail' | 'info'; action?: { label: string; run: () => void } }

export const toasts = $state({ list: [] as Toast[] })
let next = 1

export function toast(text: string, kind: Toast['kind'] = 'ok', action?: Toast['action']) {
  const id = next++
  toasts.list = [...toasts.list, { id, text, kind, action }]
  setTimeout(() => dismiss(id), kind === 'fail' ? 8000 : 4500)
}

export function dismiss(id: number) {
  toasts.list = toasts.list.filter((x) => x.id !== id)
}
