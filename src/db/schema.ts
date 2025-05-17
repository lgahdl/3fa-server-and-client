import { pgTable, serial, varchar, timestamp } from 'drizzle-orm/pg-core';

export const users = pgTable('users', {
  id: serial('id').primaryKey(),
  nome: varchar('nome', { length: 100 }).notNull(),
  numero_celular: varchar('numero_celular', { length: 20 }).notNull().unique(),
  local: varchar('local', { length: 50 }).notNull().default('Brasil'),
  senha: varchar('senha', { length: 255 }).notNull(),
  salt: varchar('salt', { length: 100 }).notNull(),
  created_at: timestamp('created_at').defaultNow(),
  updated_at: timestamp('updated_at').defaultNow()
});

// Tipos para TypeScript
export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert; 