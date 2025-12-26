document.addEventListener('DOMContentLoaded', () => {
    const container = document.getElementById('canvas-container');
    if (!container) return;

    // Scene setup
    const scene = new THREE.Scene();

    const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
    camera.position.z = 50;

    const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(window.devicePixelRatio);
    container.appendChild(renderer.domElement);

    // Particles & Lines (Network Effect)
    const particleCount = 100;
    const group = new THREE.Group();
    scene.add(group);

    const particlesData = [];
    const positions = new Float32Array(particleCount * 3);
    const particleGeometry = new THREE.BufferGeometry();
    const particleMaterial = new THREE.PointsMaterial({
        color: 0x38bdf8, // sky-400
        size: 0.5,
        transparent: true,
        opacity: 0.8,
        blending: THREE.AdditiveBlending
    });

    const r = 80;
    for (let i = 0; i < particleCount; i++) {
        const x = Math.random() * r - r / 2;
        const y = Math.random() * r - r / 2;
        const z = Math.random() * r - r / 2;

        positions[i * 3] = x;
        positions[i * 3 + 1] = y;
        positions[i * 3 + 2] = z;

        particlesData.push({
            velocity: new THREE.Vector3(
                -1 + Math.random() * 2,
                -1 + Math.random() * 2,
                -1 + Math.random() * 2
            ),
            numConnections: 0
        });
    }

    particleGeometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    const particles = new THREE.Points(particleGeometry, particleMaterial);
    group.add(particles);

    // Lines
    const lineMaterial = new THREE.LineBasicMaterial({
        color: 0x6366f1, // indigo-500
        transparent: true,
        opacity: 0.15,
        blending: THREE.AdditiveBlending
    });

    const linesGeometry = new THREE.BufferGeometry();
    const linePositions = new Float32Array(particleCount * particleCount * 3);
    linesGeometry.setAttribute('position', new THREE.BufferAttribute(linePositions, 3));
    const lines = new THREE.LineSegments(linesGeometry, lineMaterial);
    group.add(lines);

    // Mouse interaction
    let mouseX = 0;
    let mouseY = 0;
    let targetX = 0;
    let targetY = 0;

    const windowHalfX = window.innerWidth / 2;
    const windowHalfY = window.innerHeight / 2;

    document.addEventListener('mousemove', (event) => {
        // Increased sensitivity for real-time feel
        mouseX = (event.clientX - windowHalfX);
        mouseY = (event.clientY - windowHalfY);
    });

    // Animation Loop
    const clock = new THREE.Clock();

    function animate() {
        requestAnimationFrame(animate);

        // Smoothly interpolate target values
        targetX = mouseX * 0.001;
        targetY = mouseY * 0.001;

        // Rotate group based on mouse position (Stronger effect)
        group.rotation.y += 0.001; // Constant slow rotation
        group.rotation.x += (targetY - group.rotation.x) * 0.1;
        group.rotation.y += (targetX - group.rotation.y) * 0.1;

        // Parallax Camera Movement
        camera.position.x += (mouseX * 0.01 - camera.position.x) * 0.05;
        camera.position.y += (-mouseY * 0.01 - camera.position.y) * 0.05;
        camera.lookAt(scene.position);

        // Update particles
        let vertexpos = 0;
        let colorpos = 0;
        let numConnected = 0;

        // Reset connections
        for (let i = 0; i < particleCount; i++) {
            particlesData[i].numConnections = 0;
        }

        for (let i = 0; i < particleCount; i++) {
            const particleData = particlesData[i];

            // Move particles
            positions[i * 3] += particleData.velocity.x * 0.02;
            positions[i * 3 + 1] += particleData.velocity.y * 0.02;
            positions[i * 3 + 2] += particleData.velocity.z * 0.02;

            // Boundary check
            if (positions[i * 3] < -r / 2 || positions[i * 3] > r / 2) particleData.velocity.x = -particleData.velocity.x;
            if (positions[i * 3 + 1] < -r / 2 || positions[i * 3 + 1] > r / 2) particleData.velocity.y = -particleData.velocity.y;
            if (positions[i * 3 + 2] < -r / 2 || positions[i * 3 + 2] > r / 2) particleData.velocity.z = -particleData.velocity.z;

            // Check connections
            for (let j = i + 1; j < particleCount; j++) {
                const particleDataB = particlesData[j];

                const dx = positions[i * 3] - positions[j * 3];
                const dy = positions[i * 3 + 1] - positions[j * 3 + 1];
                const dz = positions[i * 3 + 2] - positions[j * 3 + 2];
                const dist = Math.sqrt(dx * dx + dy * dy + dz * dz);

                if (dist < 15) {
                    particleData.numConnections++;
                    particleDataB.numConnections++;

                    const alpha = 1.0 - dist / 15;

                    linePositions[vertexpos++] = positions[i * 3];
                    linePositions[vertexpos++] = positions[i * 3 + 1];
                    linePositions[vertexpos++] = positions[i * 3 + 2];

                    linePositions[vertexpos++] = positions[j * 3];
                    linePositions[vertexpos++] = positions[j * 3 + 1];
                    linePositions[vertexpos++] = positions[j * 3 + 2];

                    numConnected++;
                }
            }
        }

        lines.geometry.setDrawRange(0, numConnected * 2);
        lines.geometry.attributes.position.needsUpdate = true;
        particles.geometry.attributes.position.needsUpdate = true;

        renderer.render(scene, camera);
    }

    animate();

    // Resize handler
    window.addEventListener('resize', () => {
        camera.aspect = window.innerWidth / window.innerHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(window.innerWidth, window.innerHeight);
    });
});
