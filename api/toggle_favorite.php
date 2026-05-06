<?php
session_start();
header('Content-Type: application/json');
if (!isset($_SESSION['user_id'])) { echo json_encode(['success'=>false]); exit; }
$body = json_decode(file_get_contents('php://input'), true);
if (!hash_equals($_SESSION['csrf_token'] ?? '', $body['csrf_token'] ?? '')) { echo json_encode(['success'=>false]); exit; }
require_once __DIR__ . '/../config/database.php';
$id  = (int)($body['id'] ?? 0);
$fav = (int)(bool)($body['favorite'] ?? false);
$uid = (int)$_SESSION['user_id'];
$stmt = mysqli_prepare($link, "UPDATE saved_passwords SET is_favorite=? WHERE id=? AND user_id=?");
mysqli_stmt_bind_param($stmt,'iii',$fav,$id,$uid);
$ok = mysqli_stmt_execute($stmt);
echo json_encode(['success' => $ok]);
