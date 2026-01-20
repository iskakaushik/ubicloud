# frozen_string_literal: true

class Prog::Storage::ArchiveVm < Prog::Base
  subject_is :vm

  def self.assemble(vm_id)
    unless Config.storage_archive_access_key && Config.storage_archive_secret_key && Config.storage_archive_bucket
      fail "Storage archive credentials are not configured"
    end

    unless (vm = Vm[vm_id])
      fail "Vm does not exist"
    end

    unless vm.umi
      fail "Vm is not configured for UMI creation"
    end

    unless vm.vm_storage_volumes.count == 1
      fail "This prog only supports Vms with exactly one disk"
    end

    unless vm.vm_storage_volumes.first.vhost_block_backend_id
      fail "Vm is not using Ubiblk"
    end

    unless vm.vm_storage_volumes.first.key_encryption_key_1
      fail "Vm is not encrypted"
    end

    unless vm.vm_host.vhost_block_backends.any?
      fail "VmHost does not have any vhost block backend installed"
    end

    backend_version = vm.vm_storage_volumes.first.vhost_block_backend_version
    archive_bin_path = "/opt/vhost-block-backend/#{backend_version}/archive"
    begin
      vm.vm_host.sshable.cmd("test -f :archive_bin_path", archive_bin_path:)
    rescue Sshable::SshError
      fail "Archive binary not found at #{archive_bin_path}"
    end

    Strand.create(
      prog: "Storage::ArchiveVm",
      label: "stop_vm",
      stack: [{
        "subject_id" => vm_id,
        "backend_version" => backend_version
      }]
    )
  end

  label def stop_vm
    register_deadline(nil, 60 * 60)
    vm.incr_stop
    hop_wait_vm_stop
  end

  label def wait_vm_stop
    vm_state = begin
      vm.vm_host.sshable.cmd("systemctl is-active :inhost_name", inhost_name: vm.inhost_name)
    rescue Sshable::SshError => ex
      ex.stdout.strip
    end
    nap 5 unless vm_state == "inactive"
    hop_create_archive_conf
  end

  label def create_archive_conf
    conf = {
      "type" => "s3",
      "bucket" => Config.storage_archive_bucket,
      "prefix" => vm.inhost_name,
      "endpoint" => Config.storage_archive_endpoint,
      "region" => "auto",
      "credentials" => {
        "access_key_id" => encrypt_with_kek(Config.storage_archive_access_key),
        "secret_access_key" => encrypt_with_kek(Config.storage_archive_secret_key)
      }
    }

    vm.vm_host.sshable.write_file(archive_conf_path, conf.to_yaml)
    hop_create_kek_pipe
  end

  label def create_kek_pipe
    vm.vm_host.sshable.cmd("sudo mkfifo :kek_file_path", kek_file_path:)
    vm.vm_host.sshable.cmd("sudo chown :inhost_name::inhost_name :kek_file_path", inhost_name: vm.inhost_name, kek_file_path:)
    hop_run_archive
  end

  label def run_archive
    vm.vm_host.sshable.d_run(unit_name, archive_binary_path, "--config", vhost_conf_path, "--target-config", archive_conf_path, "--kek", kek_file_path, "--unlink-kek")
    write_kek_pipe
    hop_wait_archive
  end

  label def wait_archive
    state = vm.vm_host.sshable.d_check(unit_name)

    case state
    when "Succeeded"
      vm.vm_host.sshable.d_clean(unit_name)
      hop_create_machine_image
    when "NotStarted", "InProgress"
      nap 5
    else
      if state == "Failed"
        fail "Archive command failed"
      else
        Clog.emit("got unknown state from daemonizer2 check: #{state}")
        nap 60
      end
    end
  end

  label def create_machine_image
    MachineImage.create(
      name: "#{vm.boot_image}-#{Time.now.to_i}",
      bucket_prefix: SecureRandom.alphanumeric(15),
      project_id: vm.project_id,
      location_id: vm.location_id
    )

    pop "Machine Image created successfully"
  end

  def vm_storage_volume
    @vm_storage_volume ||= vm.vm_storage_volumes.first
  end

  def write_kek_pipe
    kek = vm_storage_volume.key_encryption_key_1
    kek_data = {
      "key" => kek.key.strip,
      "init_vector" => kek.init_vector.strip,
      "method" => "aes256-gcm",
      "auth_data" => Base64.strict_encode64(kek.auth_data)
    }
    vm.vm_host.sshable.write_file(kek_file_path, kek_data.to_yaml, log: false)
  end

  def encrypt_with_kek(plaintext)
    kek = vm_storage_volume.key_encryption_key_1

    cipher = OpenSSL::Cipher.new("aes-256-gcm")
    cipher.encrypt
    cipher.key = Base64.decode64(kek.key)
    cipher.iv = Base64.decode64(kek.init_vector)
    cipher.auth_data = kek.auth_data

    ciphertext = cipher.update(plaintext) + cipher.final
    auth_tag = cipher.auth_tag

    Base64.strict_encode64(ciphertext + auth_tag)
  end

  def archive_binary_path
    "/opt/vhost-block-backend/#{frame["backend_version"]}/archive"
  end

  def root_dir_path
    "/var/storage/#{vm.inhost_name}/0"
  end

  def archive_conf_path
    "#{root_dir_path}/archive.conf"
  end

  def vhost_conf_path
    "#{root_dir_path}/vhost-backend.conf"
  end

  def kek_file_path
    "#{root_dir_path}/kek.pipe"
  end

  def unit_name
    "archive_vm_#{vm.inhost_name}"
  end
end
