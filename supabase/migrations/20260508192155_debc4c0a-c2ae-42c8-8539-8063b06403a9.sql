
CREATE TABLE public.saved_searches (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL,
  module TEXT NOT NULL,
  query TEXT NOT NULL,
  result JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE public.saved_searches ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own searches select" ON public.saved_searches FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "own searches insert" ON public.saved_searches FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "own searches delete" ON public.saved_searches FOR DELETE USING (auth.uid() = user_id);
CREATE INDEX idx_saved_searches_user ON public.saved_searches(user_id, created_at DESC);

CREATE TABLE public.watchlist (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  label TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(user_id, kind, value)
);
ALTER TABLE public.watchlist ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own watch select" ON public.watchlist FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "own watch insert" ON public.watchlist FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "own watch delete" ON public.watchlist FOR DELETE USING (auth.uid() = user_id);
