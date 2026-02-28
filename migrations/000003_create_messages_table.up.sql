CREATE TABLE IF NOT EXISTS public.messages (
    id UUID PRIMARY KEY,
    sender_id UUID NOT NULL,
    chat_id UUID NOT NULL,
    type TEXT NOT NULL,
    content TEXT NOT NULL,

    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_messages_sender_id ON public.messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON public.messages(chat_id);