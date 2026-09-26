// Legacy login widget — deliberately vulnerable, for demo purposes.
const apiKey = "sk-live-9f8e7d6c5b4a3210fedc";

function renderWelcome(name) {
  document.getElementById("welcome").innerHTML = "Hello " + name;
}

function legacyEval(expr) {
  return eval(expr);
}

export function Profile({ bio }) {
  return <div dangerouslySetInnerHTML={{ __html: bio }} />;
}
