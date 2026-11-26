-- Private in-app support ticketing. Tickets are scoped to their account owner;
-- platform administrators can manage all tickets through authenticated admin routes.
CREATE TABLE IF NOT EXISTS support_tickets (
 id TEXT PRIMARY KEY,
 ticket_number TEXT NOT NULL UNIQUE,
 requester_user_id TEXT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
 subject TEXT NOT NULL,
 category TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','in_progress','waiting_on_user','resolved','closed')),
 priority TEXT NOT NULL DEFAULT 'normal' CHECK(priority IN ('low','normal','high','urgent')),
 created_at TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%fZ','now')),
 updated_at TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%fZ','now')),
 last_message_at TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_support_tickets_requester ON support_tickets(requester_user_id,last_message_at DESC);
CREATE INDEX IF NOT EXISTS idx_support_tickets_status ON support_tickets(status,last_message_at DESC);
CREATE TABLE IF NOT EXISTS support_ticket_messages (
 id TEXT PRIMARY KEY,
 ticket_id TEXT NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
 sender_user_id TEXT NOT NULL REFERENCES app_users(id),
 sender_role TEXT NOT NULL CHECK(sender_role IN ('user','admin')),
 body TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_support_ticket_messages_ticket ON support_ticket_messages(ticket_id,created_at);
