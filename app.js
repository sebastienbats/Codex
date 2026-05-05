const storeKey = 'washdog_pro_data_v1';

const state = JSON.parse(localStorage.getItem(storeKey) || '{"templates":[],"shops":[],"clients":[],"dogs":[]}');
const save = () => localStorage.setItem(storeKey, JSON.stringify(state));
const uid = () => crypto.randomUUID();

const el = id => document.getElementById(id);

function renderAll() {
  renderTemplateOptions();
  renderShopOptions();
  renderClientOptions();
  renderTemplates();
  renderShops();
  renderShowcase();
  renderClients();
  renderDogs();
  renderWashOptions();
  save();
}

function renderTemplateOptions() {
  const tpl = el('shopTemplate');
  tpl.innerHTML = '<option value="">Choisir...</option>' + state.templates.map(t => `<option value="${t.id}">${t.name}</option>`).join('');
}

function renderShopOptions() {
  const select = el('clientShop');
  select.innerHTML = '<option value="">Choisir...</option>' + state.shops.map(s => `<option value="${s.id}">${s.name}</option>`).join('');
}

function renderClientOptions() {
  const select = el('dogClient');
  select.innerHTML = '<option value="">Choisir...</option>' + state.clients.map(c => `<option value="${c.id}">${c.name} (${shopName(c.shopId)})</option>`).join('');
}

function renderWashOptions() {
  const select = el('washDogSelect');
  select.innerHTML = state.dogs.map(d => `<option value="${d.id}">${d.name} - ${d.breed}</option>`).join('');
}

const shopName = id => state.shops.find(s => s.id === id)?.name || 'Boutique inconnue';
const templateName = id => state.templates.find(t => t.id === id)?.name || 'Sans template';
const clientName = id => state.clients.find(c => c.id === id)?.name || 'Client inconnu';

function renderTemplates() {
  el('templatesList').innerHTML = state.templates.map(t => `<div class="item"><div class="item-head"><h4>${t.name}</h4><div class="actions"><button class="secondary" onclick="editTemplate('${t.id}')">Modifier</button></div></div><p>${t.desc}</p></div>`).join('');
}
function renderShops() {
  el('shopsList').innerHTML = state.shops.map(s => `<div class="item"><div class="item-head"><h4>${s.name}</h4><div class="actions"><button class="secondary" onclick="editShop('${s.id}')">Modifier</button></div></div><p>${s.address}</p><small>${s.phone} · ${s.hours} · Template: ${templateName(s.templateId)}</small></div>`).join('');
}

function renderShowcase() {
  el('showcase').innerHTML = state.shops.map(s => `<article class="item"><h3>${s.name}</h3><p><strong>Adresse:</strong> ${s.address}</p><p><strong>Horaires:</strong> ${s.hours}</p><p><strong>Téléphone:</strong> ${s.phone}</p><p><strong>Services:</strong> ${s.services.join(', ')}</p><iframe class="map-frame" loading="lazy" src="https://www.openstreetmap.org/export/embed.html?bbox=${s.lng-0.01}%2C${s.lat-0.01}%2C${s.lng+0.01}%2C${s.lat+0.01}&layer=mapnik&marker=${s.lat}%2C${s.lng}"></iframe></article>`).join('');
}

function renderClients() {
  el('clientsList').innerHTML = state.clients.map(c => `<div class="item"><div class="item-head"><h4>${c.name}</h4><div class="actions"><button class="secondary" onclick="editClient('${c.id}')">Modifier</button></div></div><p>${c.email}</p><small>Boutique: ${shopName(c.shopId)} · Points fidélité: ${c.loyalty}</small><div id="qr-client-${c.id}" class="qr"></div></div>`).join('');
  state.clients.forEach(c => {
    const container = el(`qr-client-${c.id}`);
    if (container) {
      container.innerHTML = '';
      new QRCode(container, { text: `PAYMENT|CLIENT:${c.id}|SHOP:${c.shopId}`, width: 80, height: 80 });
    }
  });
}

function renderDogs() {
  el('dogsList').innerHTML = state.dogs.map(d => `<div class="item"><div class="item-head"><h4>${d.name}</h4><div class="actions"><button class="secondary" onclick="editDog('${d.id}')">Modifier</button></div></div><p>Race: ${d.breed} · Poids: ${d.weight} kg</p><small>Client: ${clientName(d.clientId)} · Lavages: ${d.washes}</small><div id="qr-dog-${d.id}" class="qr"></div></div>`).join('');
  state.dogs.forEach(d => {
    const container = el(`qr-dog-${d.id}`);
    if (container) {
      container.innerHTML = '';
      new QRCode(container, { text: `DOG|${d.id}|WASHES:${d.washes}`, width: 80, height: 80 });
    }
  });
}

window.editTemplate = id => {
  const t = state.templates.find(x => x.id === id);
  el('templateId').value = t.id; el('templateName').value = t.name; el('templateDesc').value = t.desc;
};
window.editShop = id => {
  const s = state.shops.find(x => x.id === id);
  el('shopId').value = s.id; el('shopName').value = s.name; el('shopAddress').value = s.address;
  el('shopPhone').value = s.phone; el('shopHours').value = s.hours; el('shopLat').value = s.lat;
  el('shopLng').value = s.lng; el('shopServices').value = s.services.join(', '); el('shopTemplate').value = s.templateId;
};
window.editClient = id => {
  const c = state.clients.find(x => x.id === id);
  el('clientId').value = c.id; el('clientName').value = c.name; el('clientEmail').value = c.email; el('clientShop').value = c.shopId;
};
window.editDog = id => {
  const d = state.dogs.find(x => x.id === id);
  el('dogId').value = d.id; el('dogName').value = d.name; el('dogBreed').value = d.breed; el('dogWeight').value = d.weight; el('dogClient').value = d.clientId;
};

el('templateForm').addEventListener('submit', e => {
  e.preventDefault();
  const id = el('templateId').value;
  const data = { id: id || uid(), name: el('templateName').value, desc: el('templateDesc').value };
  id ? Object.assign(state.templates.find(t => t.id === id), data) : state.templates.push(data);
  e.target.reset(); el('templateId').value = '';
  renderAll();
});

el('shopForm').addEventListener('submit', e => {
  e.preventDefault();
  const id = el('shopId').value;
  const data = {
    id: id || uid(),
    name: el('shopName').value,
    address: el('shopAddress').value,
    phone: el('shopPhone').value,
    hours: el('shopHours').value,
    lat: Number(el('shopLat').value),
    lng: Number(el('shopLng').value),
    services: el('shopServices').value.split(',').map(s => s.trim()).filter(Boolean),
    templateId: el('shopTemplate').value
  };
  id ? Object.assign(state.shops.find(s => s.id === id), data) : state.shops.push(data);
  e.target.reset(); el('shopId').value = '';
  renderAll();
});

el('clientForm').addEventListener('submit', e => {
  e.preventDefault();
  const id = el('clientId').value;
  const data = { id: id || uid(), name: el('clientName').value, email: el('clientEmail').value, shopId: el('clientShop').value, loyalty: id ? state.clients.find(c => c.id === id).loyalty : 0 };
  id ? Object.assign(state.clients.find(c => c.id === id), data) : state.clients.push(data);
  e.target.reset(); el('clientId').value = '';
  renderAll();
});

el('dogForm').addEventListener('submit', e => {
  e.preventDefault();
  const id = el('dogId').value;
  const data = { id: id || uid(), clientId: el('dogClient').value, name: el('dogName').value, breed: el('dogBreed').value, weight: Number(el('dogWeight').value), washes: id ? state.dogs.find(d => d.id === id).washes : 0 };
  id ? Object.assign(state.dogs.find(d => d.id === id), data) : state.dogs.push(data);
  e.target.reset(); el('dogId').value = '';
  renderAll();
});

el('addWashBtn').addEventListener('click', () => {
  const dogId = el('washDogSelect').value;
  const dog = state.dogs.find(d => d.id === dogId);
  if (!dog) return;
  dog.washes += 1;
  const owner = state.clients.find(c => c.id === dog.clientId);
  if (owner) owner.loyalty += 1;
  renderAll();
});

renderAll();
