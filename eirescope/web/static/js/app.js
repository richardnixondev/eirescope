/* EireScope — Main application JavaScript */

// Tab switching
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        tab.classList.add('active');
        const target = document.getElementById('tab-' + tab.dataset.tab);
        if (target) target.classList.add('active');
    });
});

// Toggle entity details
function toggleDetails(btn) {
    const details = btn.nextElementSibling;
    if (details) {
        details.classList.toggle('hidden');
        btn.textContent = details.classList.contains('hidden') ? 'Show' : 'Hide';
    }
}

// Entity filtering
const searchInput = document.getElementById('entity-search');
const typeFilter = document.getElementById('entity-type-filter');

function filterEntities() {
    const search = (searchInput ? searchInput.value : '').toLowerCase();
    const type = typeFilter ? typeFilter.value : 'all';
    const rows = document.querySelectorAll('#entities-table tbody tr');

    rows.forEach(row => {
        const rowType = row.dataset.type || '';
        const rowValue = row.dataset.value || '';
        const matchesType = type === 'all' || rowType === type;
        const matchesSearch = !search || rowValue.includes(search) || rowType.includes(search);
        row.style.display = matchesType && matchesSearch ? '' : 'none';
    });
}

if (searchInput) searchInput.addEventListener('input', filterEntities);
if (typeFilter) typeFilter.addEventListener('change', filterEntities);
