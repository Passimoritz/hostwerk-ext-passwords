'use strict';
/*
 * KI-Werkzeug des Passwort-Managers (SDK 3.5, host.aiExtend). Bis Hostwerk 3.1 im Kern.
 * Die KI hat keinen Zugriff auf Tresore – nur ein neues Passwort erzeugen geht, das berührt keinen Tresor.
 */
function passwordsAi(pw) {
  const ctx = { pw };
  return {
    tools({ add }) {
      add('pw_generate', 'status', 'Sicheres Passwort oder Passphrase erzeugen (wird nur angezeigt, nicht gespeichert).', { length: { type: 'number', description: 'Länge (Standard 20)' }, words: { type: 'number', description: 'Wörter für eine Passphrase (0 = Zeichen)' } }, [], async ({ length = 20, words = 0 }) => { const pw = ctx.pw.generate({ length, words }); return { passwort: pw, staerke: ctx.pw.strength(pw).label }; }, { risk: 'read' });
    },
  };
}

module.exports = { passwordsAi };
