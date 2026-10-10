const { lpushQueue } = require('./redisClient');

async function enqueueEmail(to, subject, text, html) {
  const payload = {
    to,
    subject,
    text: text || '',
    html: html || '',
    created_at: new Date().toISOString()
  };
  try {
    await lpushQueue('email_queue', JSON.stringify(payload));
    return true;
  } catch (e) {
    // silently fail — Redis/queue unavailable
    return false;
  }
}

module.exports = { enqueueEmail };
