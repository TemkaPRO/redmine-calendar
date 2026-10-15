// Нужен только для того, чтобы телефон предлагал «Установить приложение».
// Ничего не кэширует: задачи всегда берутся свежими с сервера.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", event => event.waitUntil(self.clients.claim()));
self.addEventListener("fetch", () => {});
