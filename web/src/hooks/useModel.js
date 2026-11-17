import { useState, useEffect, useCallback } from 'react'
import http from '../api/http'

export function useModel() {
  const [models,    setModels]    = useState({})
  const [status,    setStatus]    = useState(null)
  const [modelInfo, setModelInfo] = useState(null)
  const [loading,   setLoading]   = useState(true)

  const refresh = useCallback(() => {
    setLoading(true)
    return Promise.all([
      http.get('/model/list'),
      http.get('/status'),
      http.get('/model'),
    ])
      .then(([modelsRes, statusRes, modelRes]) => {
        setModels(modelsRes.data)
        setStatus(statusRes.data)
        setModelInfo(modelRes.data)
      })
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    Promise.all([http.get('/model/list'), http.get('/status'), http.get('/model')])
      .then(([modelsRes, statusRes, modelRes]) => {
        setModels(modelsRes.data)
        setStatus(statusRes.data)
        setModelInfo(modelRes.data)
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  return { models, status, modelInfo, loading, refresh }
}
