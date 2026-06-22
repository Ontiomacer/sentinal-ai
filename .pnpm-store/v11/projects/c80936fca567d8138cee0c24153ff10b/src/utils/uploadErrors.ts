type ErrorRecord = Record<string, unknown>

const isRecord = (value: unknown): value is ErrorRecord =>
  typeof value === 'object' && value !== null

const stringField = (record: ErrorRecord, key: string) =>
  typeof record[key] === 'string' ? record[key] : ''

const uploadErrorText = (error: unknown) => {
  if (error instanceof Error) return error.message
  if (!isRecord(error)) return String(error)

  return [
    stringField(error, 'name'),
    stringField(error, 'code'),
    stringField(error, 'message'),
  ]
    .filter(Boolean)
    .join(' ')
}

const serverErrorMessage = (error: unknown) => {
  if (!isRecord(error) || !isRecord(error.response)) return ''

  const data = error.response.data
  if (typeof data === 'string') return data
  if (!isRecord(data)) return ''

  return stringField(data, 'detail') || stringField(data, 'message') || stringField(data, 'error')
}

const responseStatus = (error: unknown) => {
  if (!isRecord(error) || !isRecord(error.response)) return undefined
  return typeof error.response.status === 'number' ? error.response.status : undefined
}

export const shouldResetUploadFile = (error: unknown) => {
  const text = uploadErrorText(error)
  const hasResponse = isRecord(error) && Boolean(error.response)

  return (
    text.includes('ERR_UPLOAD_FILE_CHANGED') ||
    (!hasResponse && /ERR_NETWORK|Network Error/i.test(text))
  )
}

export const getUploadFailureMessage = (error: unknown) => {
  const serverMessage = serverErrorMessage(error)
  if (serverMessage) return serverMessage

  const status = responseStatus(error)
  if (status === 413) return 'This file is larger than the server accepts.'
  if (status) return `Upload failed with HTTP ${status}.`

  if (shouldResetUploadFile(error)) {
    return 'The selected file changed or the upload connection was interrupted. Select the file again and retry.'
  }

  const text = uploadErrorText(error)
  return text || 'Failed to upload evidence.'
}
